PHP_ARG_ENABLE(vandam_php, whether to enable vandam-php support,
[  --enable-vandam-php           Enable vandam-php support])

if test "$PHP_VANDAM_PHP" != "no"; then
  PHP_NEW_EXTENSION(vandam_php, vandam_php.c vandam_rasp.c hooks_php5.c hooks_php7.c, $ext_shared)
fi
