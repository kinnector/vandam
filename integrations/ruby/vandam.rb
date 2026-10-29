require 'socket'
require 'json'

module VandamRASP
  VANDAM_TELEMETRY_SOCKET = '/run/vandam/rasp_telemetry.sock'
  VANDAM_CONTROL_SOCKET = '/run/vandam/rasp_control.sock'
  
  @is_activated = false
  @verdict_cache = {}
  @telemetry_cache = {}
  @is_install_context = (ENV.key?('BUNDLE_BIN_PATH') || ENV.key?('RUBYGEMS_GEMDEPS') || $PROGRAM_NAME.include?('gem') || $PROGRAM_NAME.include?('bundle')) ? 1 : 0

  class << self
    attr_accessor :is_activated, :verdict_cache, :telemetry_cache, :is_install_context

    def get_traceback
      # Skip the first few frames inside the Vandam interceptor
      caller(3).map do |line|
        match = line.match(/(.*?):(\d+):in `(.*?)'/)
        if match
          {
            file: match[1],
            line: match[2].to_i,
            function: match[3],
            class: "",
            args: []
          }
        else
          { file: line, line: 0, function: "unknown", class: "", args: [] }
        end
      end
    end

    def ask_vandam(type, func, path, fire_and_forget: false)
      return if !@is_activated

      path_str = path.to_s
      payload_size_bytes = path_str.bytesize

      if (type == 'eval_code' || type == 'file_compile') && payload_size_bytes > 2097152
        raise SecurityError, "Vandam RASP blocked execution: Payload exceeded 2MB hard cap (#{payload_size_bytes} bytes)."
      end

      if payload_size_bytes > 4096
        path_str = path_str[0, 2048] + "\n...[TRUNCATED_MIDDLE]...\n" + path_str[-2048, 2048]
      end

      cache_key = "#{func}:#{path_str}"

      if fire_and_forget
        loc = caller_locations(1, 1).first
        top_frame = loc ? "#{loc.path}:#{loc.lineno}" : "unknown:0"
        trace_cache_key = "trace:#{func}:#{top_frame}"
      else
        if @verdict_cache.key?(cache_key)
          raise SecurityError, "Vandam RASP blocked execution of '#{func}' (Cached)" if @verdict_cache[cache_key] == 'deny'
          return
        end
      end

      payload = {
        type: type,
        pid: Process.pid,
        function: func,
        path: path_str,
        payload_size_bytes: payload_size_bytes,
        in_request: 0,
        http: {},
        trace: [],
        is_install_context: @is_install_context
      }
      
      if fire_and_forget
        if !@telemetry_cache.key?(trace_cache_key)
          payload[:trace] = get_traceback
          @telemetry_cache.clear if @telemetry_cache.size > 1000
          @telemetry_cache[trace_cache_key] = true
        end
        begin
          Socket.unix(VANDAM_TELEMETRY_SOCKET) do |sock|
            sock.write(JSON.generate(payload) + "\n")
          end
        rescue StandardError
        end
        return
      end

      begin
        Socket.unix(VANDAM_TELEMETRY_SOCKET) do |sock|
          sock.write(payload.to_json + "\n")
          
          # Wait for up to 0.5 seconds for a verdict
          if IO.select([sock], nil, nil, 0.5)
            response = sock.gets
            if response && !response.empty?
              data = JSON.parse(response)
              verdict = data['verdict'] || 'allow'
              incident_id = data['incident_id']
              
              @verdict_cache.clear if @verdict_cache.size > 1000
              @verdict_cache[cache_key] = verdict
              
              if verdict == 'deny'
                if incident_id
                  begin
                    trace_payload = { incident_id: incident_id, trace: get_traceback }
                    Socket.unix(VANDAM_TELEMETRY_SOCKET) do |tsock|
                      tsock.write(JSON.generate(trace_payload) + "\n")
                    end
                  rescue StandardError
                  end
                end
                raise SecurityError, "Vandam RASP blocked execution of '#{func}'"
              end
            else
              @verdict_cache.clear if @verdict_cache.size > 1000
              @verdict_cache[cache_key] = 'allow'
            end
          else
            @verdict_cache.clear if @verdict_cache.size > 1000
            @verdict_cache[cache_key] = 'allow'
          end
        end
      rescue SecurityError
        raise
      rescue => e
        # Fail-open if socket is down or timeout
      end
    end

    def start_activation_listener
      Thread.new do
        begin
          Socket.unix(VANDAM_CONTROL_SOCKET) do |sock|
            handshake = { type: 'hello', pid: Process.pid }
            sock.write(handshake.to_json + "\n")
            while line = sock.gets
              msg = JSON.parse(line.strip)
              @is_activated = true if msg['action'] == 'activate'
              @is_activated = false if msg['action'] == 'deactivate'
            end
          end
        rescue
          # Silently fail and remain deactivated
        end
      end
    end
  end
end

# ==========================================
# MONKEY PATCHING VIA PREPEND
# ==========================================

module VandamKernelPatch
  # 1. COMMAND EXECUTION
  def system(*args)
    VandamRASP.ask_vandam('exec_call', 'Kernel.system', args.join(' '))
    super
  end

  def exec(*args)
    VandamRASP.ask_vandam('exec_call', 'Kernel.exec', args.join(' '))
    super
  end

  def `(cmd)
    VandamRASP.ask_vandam('exec_call', 'Kernel.`', cmd)
    super
  end

  def spawn(*args)
    VandamRASP.ask_vandam('exec_call', 'Kernel.spawn', args.join(' '))
    super
  end

  # 2. DYNAMIC CODE
  def eval(code, *args)
    preview = code.to_s[0..1000]
    VandamRASP.ask_vandam('eval_code', 'Kernel.eval', preview, fire_and_forget: true)
    super
  end

  # 3. MAGIC LOADING & IMPORTS
  def require(path)
    VandamRASP.ask_vandam('file_compile', 'require', path.to_s, fire_and_forget: true)
    super
  end

  def load(path, wrap=false)
    VandamRASP.ask_vandam('file_compile', 'load', path.to_s, fire_and_forget: true)
    super
  end
end

Kernel.prepend(VandamKernelPatch)
class << Kernel
  prepend VandamKernelPatch
  freeze
end

# 4. FILE ACCESS & PERMISSIONS
module VandamFilePatch
  def open(*args, &block)
    path = args[0]
    mode = args[1] || 'r'
    type = mode.to_s.include?('w') || mode.to_s.include?('a') || mode.to_s.include?('+') ? 'file_write' : 'file_read'
    VandamRASP.ask_vandam(type, 'File.open', "#{path} (Mode: #{mode})")
    super
  end

  def read(path, *args)
    VandamRASP.ask_vandam('file_read', 'File.read', path.to_s)
    super
  end

  def write(path, *args)
    VandamRASP.ask_vandam('file_write', 'File.write', path.to_s)
    super
  end

  def chmod(mode, *paths)
    paths.each do |path|
      VandamRASP.ask_vandam('chmod', 'File.chmod', "#{path} (Perms: #{mode.to_s(8)})")
    end
    super
  end
end

class << File
  prepend VandamFilePatch
  freeze
end

class << IO
  prepend VandamFilePatch
  freeze
end

module VandamProcessPatch
  def spawn(*args)
    VandamRASP.ask_vandam('exec_call', 'Process.spawn', args.join(' '))
    super
  end
end

class << Process
  prepend VandamProcessPatch
  freeze
end

# 5. DYNAMIC CLASS/INSTANCE EVAL
class BasicObject
  alias_method :original_instance_eval, :instance_eval
  def instance_eval(*args, &block)
    if args.first.is_a?(String)
      preview = args.first.to_s[0..1000]
      ::VandamRASP.ask_vandam('eval_code', 'instance_eval', preview, fire_and_forget: true)
    end
    original_instance_eval(*args, &block)
  end
  # Do not freeze BasicObject globally to avoid breaking Ruby entirely
end

class Module
  alias_method :original_class_eval, :class_eval
  def class_eval(*args, &block)
    if args.first.is_a?(String)
      preview = args.first.to_s[0..1000]
      ::VandamRASP.ask_vandam('eval_code', 'class_eval', preview, fire_and_forget: true)
    end
    original_class_eval(*args, &block)
  end
end

# 6. C-LIBRARY / FFI LOADING
begin
  require 'fiddle'
  module VandamFiddlePatch
    def dlopen(library)
      VandamRASP.ask_vandam('dynamic_load', 'Fiddle.dlopen', library.to_s, fire_and_forget: true)
      super
    end
  end
  class << Fiddle
    prepend VandamFiddlePatch
  end
rescue LoadError
  # Fiddle not available
end

# Bootstrap activation
VandamRASP.start_activation_listener
