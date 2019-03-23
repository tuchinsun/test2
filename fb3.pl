#!/usr/bin/perl

#
#
#	Поиск файлов с вредоносным кодом по шаблону
#	
#	2016
#

use strict;
use File::Basename;
use Data::Dumper;

$| = 1;
my $path = shift;

my $delimiter			= '----------------------------------------------------------------';
my @file_pattern		= qw/php pl html/;
my $file_size_min		= 1;
my $file_size_max		= 504800;
my $max_string_length	= 2000;
my $substr				= 128; # строка с кодом в Data::Dumper
my $mlwr_base_link		= 'https://raw.githubusercontent.com/tuchinsun/test2/master/malware_base';


# Разные плохие слова, которых не должно быть в файлах. По идее.
my $shell_hackteam = 'BLESSEDSINNER|kijfmzkcc|SymlinkSA|KacakFSO|WebRootHackTools|c100Shell|SecurityAngelTeam|c99shell|r57shell|Filesman|fallagateam|w4l3XzY3|ByKymLjnk|k2ll33d|Black_SnipercPanelRipper|Ghostm1n1|PHPeMaileriscreatedbyBlackSHOP|MailerInbox-ALsa7r|farM-mOn3Y|RebelsMailer|Sphinx';
my $bad_word = 'berhasil|gagal|HackedBy|simpleSOCKS5Server|DarkShell|THISBAD|dtco4se_bp6a|SELfZAL|edoced_46esab|onfr64_qrpbqr|etalfnizg|PCT4BA6ODSE_|W3Lcome|providedbyFOPO|HaTRkFileManager|Da3sHaCkEr|RC-SHELLv|-typef-perm-04000-ls|-perm-2-typed-ls|GUNZ_BERRY';
my $word_pattern = '(' . $shell_hackteam  . '|' . $bad_word . ')';

my $time;
my $s; # scan hash
my $r; # report hash
my %mlwr_domain; # зараженные домены

# Получаем hash шаблонов вредоноса
my %MLWR = &getMalwareBase($mlwr_base_link);

# Получаем hash таблицы символов для дальнейшей подстановки
my %chrmap = &chrmap();
my $chrmap = join '|', keys %chrmap;
$chrmap = quotemeta($chrmap);
$chrmap =~ s/\\\|/|/g;
	
# Если при запуске не указана, выбираем полный путь текущей директории
$path = $ENV{'PWD'} if ( ! $path );
$time->{start} = time();

# Сортировка в Data::Dumper для наглядности. Взято из документации
$Data::Dumper::Sortkeys = \&my_filter;

#	Получаем список файлов в сканируемой директории. Необходимо будет переделывать. (((
#
my $file_pattern = &filepattern(\@file_pattern);
print 'Files: ', $file_pattern, "\n";
print "Поиск файлов ...";
my @files = `find $path  -regextype posix-egrep -type f -regex "$file_pattern"`;
print "\r";

$r->{scanfiles} = scalar @files; # кол-во сканируемых файлов

#
#
#

FILENEXT:
foreach my $file ( @files ) {
	my $file_content;
	$r->{scanned}++;
	chomp($file);
	
	my $lfile = $file;
	$lfile = substr($lfile, -128); # иногда полный путь очень длинный
	printf STDERR ("%-130s [%6d:%6d] mlwr[%3d]\r", $lfile, $r->{scanfiles}, $r->{scanned}, $r->{mlwr});
	
	# Различные операции с файлом, аттрибуты, размер и т.п.
	#
	$s->{$file}->{perm}		= &getfileperm($file);
	$s->{$file}->{size}		= &getfilesize($file);
	$s->{$file}->{mtime}	= &getfilemtime($file);
	$s->{$file}->{name}		= basename($file);
	$s->{$file}->{filename}	= $file;
	$s->{$file}->{bad_filename} = &checkFileName($s->{$file}->{name}) if ( $s->{$file}->{size} > 0 );
	
	if (( $s->{$file}->{size} < $file_size_max ) and ( $s->{$file}->{size} > $file_size_min )){
		open(FR,$file);
			while(<FR>){
				chomp();
				$s->{$file}->{lines}++;
				my $str_length = length();
				#
				# тестирование, удаление chr(XXX) и \xYY символов
				 $s->{$file}->{bad_chrmap} if ( s/($chrmap)/$chrmap{$1}/gi );
				# тестирование, удаление конкатенации "b" . '' . "as" . "" . "e_64decode"
				 $s->{$file}->{bad_concat} if ( s/['"]\.['"]//g );
				#
				$s->{$file}->{bad_count_spaces} = length($2) if ( $_ =~ /(\<\?php)?(\s{100,})(\$|\/)/);
                
				# function || str_rot13 function || strrev function
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(base64_decode|onfr64_qrpbqr|edoced_46esab)/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(eval|riny|lave)\(/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(\$GLOBALS|\$\{['"]GLOBALS['"]\})\[/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(gzinflate|tmvasyngr|etalfnizg)/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(gzuncompress|tmhapbzcerff|sserpmocnuzg)/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(str_rot13)/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(strrev)/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(rawurldecode)/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(urldecode)\(/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(fsockopen)/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(\@?file_get_contents)/ );
				$s->{$file}->{bad_func} .= $1 . ' ' if ( $_ =~ /(mail|znvy|liam)\(/ );
				#
				$s->{$file}->{max_length} = $str_length if ( $str_length > $s->{$file}->{max_length} );
				$s->{$file}->{bad_string_length} = substr($_,0,$substr) if  (( $str_length > $max_string_length ) or ( $s->{$file}->{lines} == 1 ));
			
				# Нормализация текста, удаление пробелов, переходов на новую строку и т.п.
				$_ =~ s/\s//g;
				$_ =~ s/\t//g;
				$_ =~ s/\n//;
                
                # $wp__l_='base'.(128/2).'_de'.'code'
                my $tmpv1;
                $tmpv1 = $1 / $2 if ( /\'\.\((\d+)\/(\d+)\)\.\'/ ) ;
                $tmpv1 = $1 * $2 if ( /\'\.\((\d+)\*(\d+)\)\.\'/ ) ;
                $tmpv1 = $1 + $2 if ( /\'\.\((\d+)\+(\d+)\)\.\'/ ) ;
                $tmpv1 = $1 - $2 if ( /\'\.\((\d+)-(\d+)\)\.\'/ ) ;
                s/\'\.\((\d+)\/(\d+)\)\.\'/$tmpv1/;

				$file_content .= $_;
			} # end while
		close(FR);

            my $sign_functions = () = $file_content =~ /function/g;
            $s->{$file}->{bad_count_functions} = $sign_functions if ( $sign_functions > 1000 );
            
            $s->{$file}->{bad_word} = $1 if ( $file_content =~ /$word_pattern/ );            
			#
			# Поиск malware по шаблону
			#
			# print $file_content, "\n";
			foreach my $mlwr_pattern ( keys %MLWR ) {
				# print $mlwr_pattern, "\n";

				if ( $file_content =~ /$mlwr_pattern/ ) {
					$s->{$file}->{pattern} = substr($&,0,$substr);
					$s->{$file}->{virus} = $MLWR{$mlwr_pattern};
					$r->{mlwr}++;
					next FILENEXT;
				}
			}
                
		undef($file_content);
			
	} # end if file size
        else {
            print &gettime($s->{$file}->{mtime}), ' ', $file, " Файл пропущен, превышен размер\n";
        }
} # end foreach

$time->{finish} = time();

#print Dumper($s);

print "\n\nОтчет о проверке директории \n\n";
print 'Время: ', gettime(time()), "\n";
print 'Директория: ', $path, "\n";
print $delimiter, "\n\n";
print 'Затраченное время: ', $time->{finish} - $time->{start}, "\n";
print 'Количество сигнатур: ', scalar ( keys %MLWR), "\n";
print 'Зараженных файлов: ', $r->{mlwr}, "\n";
print 'Всего файлов: ', $r->{scanfiles}, "\n";
print "\n";
print $delimiter, "\n\n";
print "\n";
print "\n";

#
print 'Найден вредоносный код ', "\n";
print $delimiter, "\n";

foreach my $file ( keys %$s ) {
	if ( $s->{$file}->{virus} ) {
		print &gettime($s->{$file}->{mtime}), ' ', $file, ' ', $s->{$file}->{virus},"\n";
		print '  >> ', $s->{$file}->{pattern}, "\n";
		print "\n";
		# print Dumper($s->{$file}), "\n";
		my ( @path ) = split(/\//, $file);
		$mlwr_domain{$path[5]} = 1; # зараженные домены
		
	}elsif ( $s->{$file}->{bad_string_length} && $s->{$file}->{bad_func}  && $s->{$file}->{bad_count_spaces} ) {
		print &gettime($s->{$file}->{mtime}), ' ', $file, ' ', $s->{$file}->{virus},"\n";
		print '  >> ', $s->{$file}->{bad_string_length}, "\n";
		print "\n";
		
		my ( @path ) = split(/\//, $file);
		$mlwr_domain{$path[5]} = 1; # зараженные домены
	}
}
print "\n\n";
#
print 'Найдены подозрительные скрипты ', "\n";
print $delimiter, "\n";
foreach my $file ( keys %$s ) {
	if ( $s->{$file}->{virus} !~ /PHP/ ) {
	
		# Здесь дополнительные условия. Исходя из опыта.
		if (( $s->{$file}->{lines} < 3 )&&($s->{$file}->{bad_string_length} > 15000)) {
            print &gettime($s->{$file}->{mtime}), ' ', $file, "\n";
			print Dumper($s->{$file});
		}
		
		elsif (($s->{$file}->{lines} < 3)&&($s->{$file}->{bad_func})){
            print &gettime($s->{$file}->{mtime}), ' ', $file, "\n";
			print Dumper($s->{$file});
		}
		
		elsif (($s->{$file}->{lines} < 3)&&($s->{$file}->{bad_count_spaces})) {
            print &gettime($s->{$file}->{mtime}), ' ', $file, "\n";
			print Dumper($s->{$file});
		}
		elsif (($s->{$file}->{bad_word})){
            print &gettime($s->{$file}->{mtime}), ' ', $file, "\n";
			print Dumper($s->{$file});
		}
		
		elsif (($s->{$file}->{bad_func} < 3)&&($s->{$file}->{bad_count_spaces})) {
            print &gettime($s->{$file}->{mtime}), ' ', $file, "\n";
			print Dumper($s->{$file});
		}
        elsif ( $s->{$file}->{bad_count_functions} ) {
            print &gettime($s->{$file}->{mtime}), ' ', $file, "\n";
        	print Dumper($s->{$file});
        }
# Много файлов у которых кол-во точек, ну очень большое свыше 4 тыс.
#        elsif ( $s->{$file}->{bad_count_dots} ) {
#            print &gettime($s->{$file}->{mtime}), ' ', $file, "\n";
#        	print Dumper($s->{$file});
#        }
#        else {
#            print &gettime($s->{$file}->{mtime}), ' ', $file, "\n";
#            print Dumper($s->{$file});
#        }

# показывать все, оч много смотреть, глаза можно поломать		
#		if (( $s->{$file}->{bad_filename} > 10 ) || $s->{$file}->{bad_string_length} || ( $s->{$file}->{bad_count_spaces} ) || ( $s->{$file}->{bad_string_length} > 5000 ) || ($s->{$file}->{bad_words}) || $s->{$file}->{cmd_eval} || $s->{$file}->{globals} ) {
#			print Dumper($s->{$file});
#		}
	} # end if
}

print "\n\n", 'Сайт(ы) заблокирован(ы): ', "\n";
print $delimiter, "\n";
foreach ( keys %mlwr_domain ) {
	print $_,"\n";
}

print "\n\n";


#
#
#

# Маска для поиска файлов
sub filepattern {
	my $pattern = shift;
	my $result = '.*\.(';
	foreach ( @$pattern ) {
		$result .= $_ . '|';
	}
	$result =~ s/\|$/)*/;

	return $result;
}

#	Установленные права на файл
#
sub getfileperm {
	my $file = shift;
	return sprintf ("%04o",(stat($file))[2]);
}

#	Размер файла
#
sub getfilesize {
	my $file = shift;
	return (stat($file))[7];
}

#	Время изменения файла
#
sub getfilemtime {
	my $file = shift;
	return (stat($file))[9];
}

#	Создаем строку шаблона
#
sub getmlwr {
	my $mlwr = shift;
	my $result;
	foreach ( keys %$mlwr ){
		$result .= $_ . '|';
	}
	$result =~ s/\|$//;
	return $result;
}

#	Время в нужном формате
#
sub gettime {
	my $time = shift;
	my($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($time);
	return sprintf("%02d-%02d-%04d %02d:%02d:%02d",$mday,$mon+1,$year+1900,$hour,$min,$sec);
}

#	Скачиваем базу с шаблонами вредоноса
#
sub getMalwareBase {
	my $link = shift;
	my %result;
	my $file = '/dev/shm/malware_base';
	system("wget -O $file -q $link");
	
	if ( ! -s $file ) {
		die ("can't find malware base\n");
	}
	
	open(FR, $file );
		while(<FR>) {
			if ( $_ !~ /^$/ ) {
				my ($description, $pattern) = split(/\s+/);
				$result{$pattern} = $description;
			} # end if
		} # end while
	close(FR);
	unlink $file;
	
	return %result;
}

#	Проверка имени файла
#
sub checkFileName {
	my $file = shift;
	my $score;
	
	$score += 11 if ( $file =~ /^\./ );
	$score += 12 if( $file =~ /[a-zA-Z]\d\w?\d/ );
	$score += 25 if( $file =~ /(.+?)\.(php|pl)\..+/ );
	
	return $score;
}

#	Таблица символов
#
sub chrmap {
    my %chrmap;
    my $index;
    my @chr = qw/. * # _ ( ) a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 0 1 2 3 4 5 6 7 8 9/;
	push @chr, ' ';
	
    foreach ( @chr ) {
        $index = 'chr(' . ord() . ')';
        $chrmap{$index} = '"' . $_ . '"';
		
		# Шестнадцатиричные значение ASCII
        $index = '\x' . sprintf("%2.2x", ord());
        $chrmap{$index} = $_;
		
		# Шестандцатиричные uppercase значение ASCII
		$index = '\x' . uc(sprintf("%2.2x", ord()));
		$chrmap{$index} = $_;
		
		# Восьмиричное значение ASCII
		$index = '\\' . sprintf("%03o", ord());
		$chrmap{$index} = $_;
		
		# Восьмиричное значение ASCII без 0
		$index = '\\' . sprintf("%2o", ord());
		$chrmap{$index} = $_;
    }

	# print Dumper(%chrmap);
    return %chrmap;
}

#	Функция сортировки hash Data::Dumper. Взято из документации
#
sub my_filter {
        my ($hash) = @_;
        return [(sort keys %$hash)];
}
