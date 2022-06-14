from os import _exit

import kivy
from kivy.app import App
from kivy.properties import ObjectProperty, StringProperty
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.widget import Widget
from kivy.uix.label import Label

from labtcpclient import LabTcpClient

kivy.require('1.10.0')

BUFFER_SIZE = 4096
HOST = '127.0.1.1'
PORT = 9999

CLT = LabTcpClient(HOST, PORT, BUFFER_SIZE)


class PopupWindow(Widget):
    def btn(self):
        popFun()


def popFun(title, message):
    window = Popup(title=title,
                   content=Label(text=message),
                   size_hint=(None, None), size=(400, 400))
    window.open()


class UnAuth(Screen):
    """Экран для неавторизированного пользователя"""
    def __init__(self, **kwargs):
        super(UnAuth, self).__init__(**kwargs)

class LoginWindow(Screen):
    email = ObjectProperty(None)
    pwd = ObjectProperty(None)

    def __init__(self, **kwargs):
        super(LoginWindow, self).__init__(**kwargs)

    def LoginBtn(self):
        if self.username.text != "":
            if self.password.text != "":
                reg_data = {'username': self.username.text,
                            'password': self.password.text, 'send_key': 'LOGIN'}
                CLT.send_data_server(reg_data)
                data = CLT.recv_data_server()
                if data['status'] == 'SUCCESS':
                    # Уже авторизировался и можно открыть главный интерфейс
                    print("main menu")
                else:
                    popFun("Error", data['message'])
            else:
                popFun("Error", "Enter your password")
        else:
            popFun("Error", "Enter your username")


class SignupWindow(Screen):
    username = ObjectProperty(None)
    password = ObjectProperty(None)

    def SignUpBtn(self):
        if self.username.text != "":
            if self.password.text != "":
                reg_data = {'username': self.username.text,
                            'password': self.password.text, 'send_key': 'REGISTRATION'}
                CLT.send_data_server(reg_data)
                data = CLT.recv_data_server()
                if data['status'] == 'SUCCESS':
                    # Уже авторизировался и можно открыть главный интерфейс
                    print("main menu")
                else:
                    popFun("Error", data['message'])
            else:
                popFun("Error", "Enter your password")
        else:
            popFun("Error", "Enter your username")


SCREENS = {0: (UnAuth, "UnAuth"), 1: (
    LoginWindow, "Login"), 2: (SignupWindow, "Signup")}


class MyApp(App):

    def build(self):
        """Выполнить сразу после run()"""

        # Создание экранов
        self.screen_manager = ScreenManager()
        for i in range(len(SCREENS)):
            self.screen_manager.add_widget(SCREENS[i][0](name=SCREENS[i][1]))
        return self.screen_manager

    def on_start(self):
        """Выполнить предварительную сборку"""
        pass

    def build_config(self, config):
        """Если файл *.ini не существует,
        он создается с этими значениями по умолчанию.
        Если отсутствуют только строки, он ничего не делает!
        """

        config.setdefaults('kivy',
                           {'log_level': 'debug',
                            'log_name': 'tcpclient_%y-%m-%d_%_.txt',
                            'log_dir': '/log',
                            'log_enable': '1'})

    def go_unauth(self):
        """Открыть главную авторизации"""
        self.screen_manager.current = ("UnAuth")

    def go_login(self):
        """Открыть страницу Авторизации"""
        self.screen_manager.current = ("Login")

    def go_signup(self):
        """Открыть страницу Регистрации"""
        self.screen_manager.current = ("Signup")

    def do_quit(self):
        """Кнопка выхода из приложения"""

        # Kivy
        MyApp.get_running_app().stop()

        # Extinction de tout
        _exit(0)


if __name__ == "__main__":
    MyApp().run()
