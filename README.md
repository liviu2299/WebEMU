# WebEMU - x86 64bit emulator based on Unicorn-engine

  The purpose of this project is to create a software platform that allows the interpretation of
the assembly language. The application is developed for educational purposes and is intended for
people who want to get acquainted with the basic concepts of low-level programming providing
them a dynamic learning environment. The project consists in a module capable of emulating
the x86 microprocessor architecture and an intuitive interface through which the user can follow
the process of compiling and executing a code sequence.

## <u>Stack</u>

### Front
- ReactJs
- CodeMirror
- MaterialUI
- react-table / react-window

### Back
- Flask
- Flask-Session

### Emulation
- Unicorn-engine
- Keystone-engine
- Capstone-engine

## App

![sample](/client/public/webapp.png)

## Setup

In ./backend:

Generate a venv.

```pip install -r 'requirements.txt && flask run```

In ./client:

```npm install --legacy-peer-deps && npm start```
