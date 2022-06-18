import os

import kivy
from kivy.app import App
from kivy.properties import ObjectProperty, StringProperty
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.widget import Widget
from kivy.uix.label import Label
from kivy.properties import ListProperty
from plyer import filechooser

from labtcpclient import LabTcpClient

kivy.require('1.10.0')

BUFFER_SIZE = 4096
HOST = '127.0.1.1'
PORT = 9999

CLT = LabTcpClient(HOST, PORT, BUFFER_SIZE)
SCREENMANAGER = ScreenManager()

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
                CLT.send_data_server(reg_data, True)
                data = CLT.recv_data_server(True)
                print(data)
                if data:
                    if data['status'] == 'SUCCESS':
                        # Уже авторизировался и можно открыть главный интерфейс
                        SCREENMANAGER.current = ("FileChoise")
                    else:
                        popFun("Error", data['message'])
                else:
                    popFun("Error", 'No connection to server')
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
                CLT.send_data_server(reg_data, True)
                data = CLT.recv_data_server(True)
                if data:
                    if data['status'] == 'SUCCESS':
                        # Уже авторизировался и можно открыть главный интерфейс
                        SCREENMANAGER.current = ("FileChoise")
                        print("main menu")
                    else:
                        popFun("Error", data['message'])
                else:
                    popFun("Error", 'No connection to server')
            else:
                popFun("Error", "Enter your password")
        else:
            popFun("Error", "Enter your username")

class FileChoise(Screen):
    selection = ListProperty([])

    def file_choose(self):
        '''
        Вызовите plyer filechooser API для запуска действия filechooser.
        '''
        filechooser.open_file(on_selection=self.handle_selection)

    def handle_selection(self, selection):
        # Функция обратного вызова для обработки ответа выбора из Activity.
        self.selection = selection
        file_name = os.path.basename(self.selection[0])
        data = {'file_name': file_name, 'send_key': 'FILE UPLOAD'}

        with open(file_name, 'rb') as f:
            data_file = f.read()
        
        CLT.send_data_server(data, True)
        if CLT.recv_data_server(True)['status'] == 'OK':
            CLT.send_data_server(data_file, False)
        


SCREENS = {0: (UnAuth, "UnAuth"), 1: (
    LoginWindow, "Login"), 2: (SignupWindow, "Signup"), 3: (FileChoise, "FileChoise")}


class MyApp(App):

    def build(self):
        """Выполнить сразу после run()"""

        # Создание экранов
        for i in range(len(SCREENS)):
            SCREENMANAGER.add_widget(SCREENS[i][0](name=SCREENS[i][1]))
        self.screen_manager = SCREENMANAGER
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

    def go_filechoise(self):
        self.screen_manager.current = ("FileChoise")

    def do_quit(self):
        """Кнопка выхода из приложения"""

        # Kivy
        MyApp.get_running_app().stop()

        # Extinction de tout
        os._exit(0)


if __name__ == "__main__":
    MyApp().run()
