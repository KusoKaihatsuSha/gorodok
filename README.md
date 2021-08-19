# Sistema gorod sync
	Программа по взаимодействию с сервисами / прототипами сервисов с вычислительным центром Система город
	Страна: РФ
	Регион: 22(вероятно только для этого региона)
	Программа при наличии настроек в setings.ini скачивает реестры, загружает реестры и скачивает показания в АРМ Системы Город

		-d           загрузить реестры, которые ещё не загружались

		-d -manual   загрузить реестры за последние 10 дней

		-meter       загрузить показания

		-u           выгрузить реестры

	Содержание файла настроек

	[General]

	path_download_meter = \\10.10.10.10\folder\meters.txt # путь до файла загрузки показаний из арм

	path_download_data_zip = \\10.10.10.10\folder\Pays\ # путь до архивов папки загрузки

	path_download_data = \\10.10.10.10\folder\Pays\ # путь до папки загрузки

	path_upload_data_zip = \\10.10.10.10\folder\Saldo\ # путь до файла архивов выгрузки

	path_upload_data = \\10.10.10.10\folder\Saldo\ # путь до папки выгрузки

	path_logs = \\10.10.10.10\folder\Logs\ # путь до логов  загрузки и выгрузки

	mail_sender_alias = INFO # отправитель в письме

	mail_sender_email = info@info.info # отправитель в письме

	mail_recipients_email = r1@info.info;r2@info.info # получатели писем

	mail_server = 10.10.10.10:25 # почтовый сервер. предполагается доступ без аутентификации

	mail_error_subject = "error" # заголовок сообщения об ошибке

	mail_error_body = <b style='color:red'>ERROR</b> # вид сообщения об ошибке

	arm_server = https://172.0.0.1 # путь до арм

	arm_login = login # логин

	arm_password = password # пароль

	arm_trying = 5 # количество попыток соединения с арм

	upload_mask = filename_(x|y|z|1)\.txt # маска выгрузки файлов

	unzip_without_subfolder = yes # раскаковка без учета подкаталогов
	
	delete_ziped = yes # удалять ли архивы

	last_days = 10 # количество дней ручной загрузки
