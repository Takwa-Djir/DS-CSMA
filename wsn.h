
//******************************************************************//
//*     Header f i l e ( . h) o f a . cc f i l e d e s c r i b e the beha viou r o f the module                   *//
//*******************************************************************//
#ifndef newprotocol_h
#define newprotocol_h

#include <agent.h>
#include <mobilenode.h>
#include <tclcl.h>
#include <packet.h>
#include <address.h>
#include <ip.h>
#include <timer-handler.h>
#include <rng.h>
#include <trace.h>
#include "newprotocol_header.h"
#include "newprotocol_rxdatadb.h"

#define JITTER (rng_.uniform(0, 1))

class NewprotocolAgent; // forward declaration

// Timers
class Newprotocol_PktTimer : public TimerHandler {
protected:
    NewprotocolAgent* agent_;
    virtual void expire(Event* e);
public:
    Newprotocol_PktTimer(NewprotocolAgent* agent) : TimerHandler() {
        agent_ = agent;
    }
};

// if you need more timers, add the necessary stuff for them here

class SlotCounterTimer : public TimerHandler {
protected:
    NewprotocolAgent* agent_;
    virtual void expire(Event* e);
public:
    SlotCounterTimer(NewprotocolAgent* agent) : TimerHandler() {
        agent_ = agent;
    }
};

/* ******************************************************************/

class NewprotocolAgent : public Agent {
    friend class Newprotocol_PktTimer;
    friend class SlotCounterTimer;
public:
    NewprotocolAgent(u_int32_t);
    virtual int command(int argc, const char*const* argv);
    virtual void recv(Packet*, Handler*);
    virtual void timeout(int);
    u_int16_t MySlot1_;

protected:
    Newprotocol_PktTimer pkt_timer_;   // timer for sending packets
    SlotCounterTimer SlotCounterTm_;

    int SWTCL_;			    // Spread Starting Transmission Time window for DS-CSMA MAC
    int MACMethode_;		    // define the MAC Methode used 
    double interval_;               // sending interval
    double Slotinterval_;
    bool running_;                  // periodic sending
    u_int32_t wsnID_;            // own ID

    u_int16_t MaxSlotVicinity_;			
    u_int16_t MySlot_;		
    u_int16_t MyminASlot_; 
    u_int16_t MyMaxASlot_;

    u_int32_t CurrentSlotNumber;
    u_int32_t FameSize;		/*****************************************************/

    newprotocol_rxdatadb rxdb_;        // received packets database
    Trace* logtarget_;              // for logging
    RNG rng_;                       // random number generator, for the jitter
    double jitterfactor_;           // multiplication-factor for the tx-jitter
    double crypto_delay_;           // signing and verification delay [s]
    
    void sendRBC_pkt();            // broadcast a RBC message
    
    void recvRBC(Packet*);          // processing of received RBC messages
    
    void reset_newprotocol_pkt_timer();    // for the timer
    
    void reset_SlotCounter_timer();

    void BeginCCHInterval();

};

#endif

