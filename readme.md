##  Запуск проекта:

pip install -r requirements.txt
python3 manage.py runserver 0.0.0.0:8077
___

## Запуск проекта через docker:
### Доступен по порту :8077

docker-compose up
docker-compose run web python manage.py createsuperuser -- создать суперпользователя
___

## API эндпойнты:


### http://localhost:8077/api/token/ -- выдает пару ключей Access и Refresh ключей для пользователя с идендтификатором
### http://localhost:8077/api/token/refresh/ -- обновление пары токенов путём ввода Refresh токена

## HEADER_TYPES: 'Bearer'
http://localhost:8077/auth/api/user_create/
* GET вывести всех пользователей из базы 
* POST зарегестрировать пользователя

{
	"password": "Пароль",
	"username": "Имя пользователя"
}

http://localhost:8077/auth/api/user_update/<int:pk>/
* GET получить пользователя по ид
* PUT изменить пользователя
* DELETE удалить пользователя
	
