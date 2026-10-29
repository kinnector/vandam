use ExtUtils::MakeMaker;
WriteMakefile(
    NAME              => 'Vandam',
    VERSION_FROM      => 'lib/Vandam.pm',
    PREREQ_PM         => {},
    ABSTRACT_FROM     => 'lib/Vandam.pm',
    AUTHOR            => 'Vandam RASP',
    LIBS              => [''],
    DEFINE            => '',
    INC               => '-I.',
);
