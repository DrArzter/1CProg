import PySimpleGUI as sg
import sqlite3
import hashlib
import datetime
import os
import time
import math as m


conn = sqlite3.connect('database.db')
cursor = conn.cursor()
roles = ["Administrator", "Kladovshik", "Injener", "Testirovshik", "Rukovoditel proizvodstva", "Rukovoditel otdela zakupok",
 "Menedjer po zakupkam", "Rukovoditel otdela prodaj", "Menedjer po prodajam"]

permitRoles = ["Administrator", "Kladovshik", "Injener", "Rukovoditel proizvodstva", "Rukovoditel otdela zakupok", "Menedjer po zakupkam"]


def sanitizeInput(input):
    ##TODO: Sanitize input
    forbiddenChars = ['\\', '/', ':', '*', '?', '"', '<', '>', '|', ' ', '(', ')', '$', '%', '&', '卐']
    for char in input:
        if char in forbiddenChars:
            input = input.replace(char, '')
    return input
    

def initializeDatabase():
    ##TODO: Initialize the database
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(255), password VARCHAR(255), role VARCHAR(255) NULL, last_login DATETIME, last_logout DATETIME, last_login_device VARCHAR(255) NULL)')
    cursor.execute('CREATE TABLE IF NOT EXISTS components (id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(255), article VARCHAR(255), type VARCHAR(255), weight INT, production_date DATETIME)')
    # sqlite3.OperationalError: incomplete input
    # cursor.execute('CREATE TABLE IF NOT EXISTS robots (id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(255), article VARCHAR(255), weight INT, condition VARCHAR(255), components VARCHAR(255)')
    conn.commit()
    return True


def registration(name, password):
    ##TODO: Register a new user
    cursor.execute('SELECT * FROM users WHERE name = ?', (name,))
    if cursor.fetchone():
        print('User already exists')
        return False
    else:
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO users (name, password) VALUES (?, ?)', (name, hashed_password))
        conn.commit()
        return True
    

def hash_password(password):
    ##TODO: Hash a password
    return hashlib.sha256(password.encode()).hexdigest()

def checkRole(user_id):
    ##TODO: Check role of a user
    cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
    role = cursor.fetchone()[0]
    return role


def login(name, password, device):
    ##TODO: Login a user
    hashed_password = hash_password(password)
    cursor.execute('SELECT * FROM users WHERE name = ? AND password = ?', (name, hashed_password))
    user = cursor.fetchone()
    if user:
        cursor.execute('UPDATE users SET last_login = ?, last_login_device = ? WHERE name = ?', (datetime.datetime.now(), device, name))
        conn.commit()
        return user
    else:
        print('Wrong name or password')
        return False


def logout(user_id):
    ##TODO: Logout a user
    cursor.execute('UPDATE users SET last_logout = DATETIME() WHERE id = ?', (user_id,))
    conn.commit()
    return True


def changeName(admin_id, target_user_id, new_name):
    #TODO: Change name of a user
    if checkRole(admin_id) == 'Administrator':
        cursor.execute('UPDATE users SET name = ? WHERE id = ?', (new_name, target_user_id))
        conn.commit()
        return True
    else:
        print('Only administrators can change names')
        return False
    

def changeRole(admin_id, target_user_id, role):
    #TODO: Change role of a user
    if checkRole(admin_id) == 'Administrator':
        cursor.execute('UPDATE users SET role = ? WHERE id = ?', (role, target_user_id))
        conn.commit()
        return True
    else:
        print('Only Administrators can change roles')
        return False
    

def changePassword(admin_id, target_user_id, new_password):
    #TODO: Change password of a user
    if checkRole(admin_id) == 'Administrator':
        cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hash_password(new_password), target_user_id))
        conn.commit()
        return True
    else:
        print('Only administrators can change passwords')
        return False


def deleteUser(admin_id, target_user_id):
    #TODO: Delete a user
    if checkRole(admin_id) == 'Administrator' and checkRole(target_user_id) != 'Administrator':
        cursor.execute('DELETE FROM users WHERE id = ?', (target_user_id,))
        conn.commit()
        return True
    else:
        print('Only administrators can delete users')
        return False
    

def getUsers(admin_id):
    #TODO: Get all users
    if checkRole(admin_id) == 'Administrator':
        cursor.execute('SELECT * FROM users')
        result = [list(i) for i in cursor.fetchall()]
        return result
    else:
        print('Only administrators can get users')
        return False
    
    
def getComponents(user_id):
    #TODO: Get all components
    if checkRole(user_id) in permitRoles:
        cursor.execute('SELECT * FROM components')
        result = [list(i) for i in cursor.fetchall()]
        return result
    else:
        print('Your role is not permitted to get components')
        return False
    
def changeComponentName(user_id, component_id, new_name):
    #TODO: Change name of a component
    if checkRole(user_id) in permitRoles:
        cursor.execute('UPDATE components SET name = ? WHERE id = ?', (new_name, component_id))
        conn.commit()
        return True
    else:
        print('Your role is not permitted to change components')
        return False

def changeComponentArticle(user_id, component_id, new_article):
    #TODO: Change article of a component
    if checkRole(user_id) in permitRoles:
        cursor.execute('UPDATE components SET article = ? WHERE id = ?', (new_article, component_id))
        conn.commit()
        return True
    else:
        print('Your role is not permitted to change components')
        return False
    
def changeComponentType(user_id, component_id, new_type):
    #TODO: Change type of a component
    if checkRole(user_id) in permitRoles:
        cursor.execute('UPDATE components SET type = ? WHERE id = ?', (new_type, component_id))
        conn.commit()
        return True
    else:
        print('Your role is not permitted to change components')
        return False
    
def changeComponentWeight(user_id, component_id, new_weight):
    #TODO: Change weight of a component
    if checkRole(user_id) in permitRoles:
        cursor.execute('UPDATE components SET weight = ? WHERE id = ?', (new_weight, component_id))
        conn.commit()
        return True
    else:
        print('Your role is not permitted to change components')
        return False
    
def changeComponentProductionDate(user_id, component_id, new_production_date):
    #TODO: Change production date of a component
    if checkRole(user_id) in permitRoles:
        cursor.execute('UPDATE components SET production_date = ? WHERE id = ?', (new_production_date, component_id))
        conn.commit()
        return True
    else:
        print('Your role is not permitted to change components')
        return False
    
def getCerteinComponents(user_id, component_type):
    #TODO: Get certain components
    if checkRole(user_id) in permitRoles:
        cursor.execute('SELECT * FROM components WHERE type = ?', (component_type,))
        result = [list(i) for i in cursor.fetchall()]
        return result
    else:
        print('Your role is not permitted to get certain components')
        return False


def authWindow():
    c = 0
    sg.theme('DarkAmber')
    layout = [
        [sg.Text('', key="-STATE-")],
        [sg.Text('Enter login')],[sg.InputText()],
        [sg.Text('Enter password')],[sg.InputText()],
        [sg.Button('Login')],[sg.Button('Register')]
    ]
    window = sg.Window('Autorization window', layout)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == 'Exit': # if user closes window or clicks cancel
            break
        if event == "Register":
            registration(sanitizeInput(values[0]), sanitizeInput(values[1]))
        if event == "Login":
            status = login(sanitizeInput(values[0]), sanitizeInput(values[1]), os.environ.get('USERNAME'))
            if str(type(status)) == "<class 'bool'>":
                if c <= 3:
                    window["-STATE-"].Update("Wrong login or password")
                    c += 1
                    timer = time.time()
                else:
                    window["-STATE-"].Update(f"Wrong login or password, {m.ceil(300 - (time.time() - timer))} seconds left")
                    if time.time() - timer > 300:
                        c = 0
            else:
                if c <= 3:
                    break
    window.close()
    return status


def adminWindow(status, users):
    sg.theme('DarkAmber')
    layout = [
        [sg.Text(f'role: {status[3]}', key="-STATE-")],
        [[sg.Button(f'Name: {users[i][1]}; Role: {users[i][3]}; Last login: {users[i][4]}; Last logout {users[i][5]}',
        size=(80, 2), key=f"-USER{i}-")] for i in range(len(users))]
    ]
    window = sg.Window('Automatization program', layout)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == 'Exit': # if user closes window or clicks cancel
            break
        if "-USER" in event:
            changeWindow(window, users, int(event[5:][:-1]), status)
    window.close()
    
    
def changeWindow(win, users, selected, status):
    sg.theme('DarkAmber')
    layout = [
        [sg.Text(f'Name'), sg.InputText(users[selected][1])],
        [sg.Text(f'Password'), sg.InputText()],
        [sg.Text(f'Role'), sg.Combo(roles, font=('Arial Bold', 14),  expand_x=True, enable_events=True,  readonly=True, key='-COMBO-')],
        [sg.Button('Delete user'), sg.Button('Confirm changes')]
    ]
    window = sg.Window('Change parameters', layout)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == 'Exit': # if user closes window or clicks cancel
            break
        if event == 'Confirm changes':
            if (sanitizeInput(values[0]) != "") and (sanitizeInput(values[0]) != users[selected][1]):
                changeName(status[0], users[selected][0], sanitizeInput(values[0]))
                users[selected][1] = sanitizeInput(values[0])

            if (values["-COMBO-"] != "") and (values["-COMBO-"] != users[selected][3]):
                changeRole(status[0], users[selected][0], values["-COMBO-"])
                users[selected][3] = values["-COMBO-"]

            if (sanitizeInput(values[1]) != ""):
                changePassword(status[0], users[selected][0], sanitizeInput(values[1]))
            win[f"-USER{selected}-"].Update(f'Name: {sanitizeInput(values[0])}; Role: {sanitizeInput(values["-COMBO-"])}; Last login: {users[selected][4]}; Last logout {users[selected][5]}')
            return
        if event == 'Delete user':
            deleteUser(status[0], users[selected][0])
            win[f"-USER{selected}-"].Update(visible=False)
            return
    window.close()


def main():
    ##TODO:
    #Main window for components
    #Components redacting BD DONE
    #Main window for robots

    #Create 1 user for every role

    initializeDatabase()
    status = authWindow()
    adminWindow(status, getUsers(status[0]))
    logout(status[0])
    conn.close()    


if __name__ == "__main__":
    main()