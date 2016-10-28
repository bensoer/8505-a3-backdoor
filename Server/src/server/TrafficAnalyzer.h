//
// Created by bensoer on 18/10/16.
//

#ifndef INC_8505_A3_BACKDOOR_TRAFFICANALYZER_H
#define INC_8505_A3_BACKDOOR_TRAFFICANALYZER_H


class TrafficAnalyzer {

private:
    TrafficAnalyzer();

    static TrafficAnalyzer * instance;

public:
    static TrafficAnalyzer * getInstance();

    void addPacket();

    bool canMakePacket();

    int makeAppropriatePacket();
};


#endif //INC_8505_A3_BACKDOOR_TRAFFICANALYZER_H
