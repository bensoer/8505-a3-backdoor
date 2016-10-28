//
// Created by bensoer on 18/10/16.
//

#include "TrafficAnalyzer.h"

TrafficAnalyzer * TrafficAnalyzer::instance = nullptr;

TrafficAnalyzer * TrafficAnalyzer::getInstance() {
    if(TrafficAnalyzer::instance == nullptr){
        TrafficAnalyzer::instance = new TrafficAnalyzer();
    }

    return TrafficAnalyzer::instance;
}

TrafficAnalyzer::TrafficAnalyzer() {

}

void TrafficAnalyzer::addPacket() {

}

bool TrafficAnalyzer::canMakePacket() {

}

int TrafficAnalyzer::makeAppropriatePacket() {

}