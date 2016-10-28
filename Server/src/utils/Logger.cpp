//
// Created by bensoer on 25/10/16.
//

#include <iostream>
#include "Logger.h"

bool Logger::isDebug = false;

void Logger::debug(string message) {
    if(Logger::isDebug){
        Logger::println(message);
    }
}

void Logger::println(string message) {
    cout << message << endl;
}

void Logger::print(string message) {
    cout << message;
}

void Logger::error(string message) {
    cerr << message << endl;
}

void Logger::setDebug(bool state) {
    Logger::isDebug = state;
}