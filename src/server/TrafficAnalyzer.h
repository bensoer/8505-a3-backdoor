//
// Created by bensoer on 18/10/16.
//

#ifndef INC_8505_A3_BACKDOOR_TRAFFICANALYZER_H
#define INC_8505_A3_BACKDOOR_TRAFFICANALYZER_H


class TrafficAnalyzer {

public:
    TrafficAnalyzer();

    void addPacket();

    bool canMakePacket();

    int makeAppropriatePacket();
};


#endif //INC_8505_A3_BACKDOOR_TRAFFICANALYZER_H
