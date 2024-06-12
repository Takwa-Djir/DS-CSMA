

#include <assert.h>
#include "wsnrbc.h"
#include "random.h"
int hdr_wsn::offset_;


// define our Packet Headers
static class wsnRBCHeaderClass : public PacketHeaderClass {
public:
    wsnRBCHeaderClass() : PacketHeaderClass("PacketHeader/wsnRBC",
                                                    sizeof(hdr_all_wsn)) {
        bind_offset(&hdr_wsn::offset_);
    }
} class_wsnrbchdr;


// define a TCL-class
static class wsnRBCClass : public TclClass {
public:
    wsnRBCClass() : TclClass("Agent/wsnRBC") { };
    
    TclObject* create(int argc, const char*const* argv) {
        if(argc != 5) {
            printf("Creating wsnRBC-Agent: argc not equal 5: %d\n", argc);
            exit(1);
        }
        return (new wsnRBCAgent(atoi(argv[4])));  // pass the ID to
                                                    // the constructor
    }
} class_wsnrbc;


// to reset the timer
void wsnRBCAgent::reset_wsnrbc_pkt_timer() {
    pkt_timer_.resched((double)interval_);
}

void wsnRBCAgent::reset_SlotCounter_timer() {
    SlotCounterTm_.resched((double)Slotinterval_);
}

// called when the timer expires
void wsnRBC_PktTimer::expire(Event*) {
    agent_->timeout(0);
}

void SlotCounterTimer::expire(Event*) {
 
agent_->sendRBC_pkt();
}

// ! if you need more timers, add the necessary stuff for them here


// the constructor
wsnRBCAgent::wsnRBCAgent(u_int32_t id) : Agent(PT_wsnRBC),
                                                        pkt_timer_(this), SlotCounterTm_(this) {  
    // please note that in the previous line the pkt_timer_ object is
    // already initialized
    
    wsnID_ = id;
    running_ = false;

    MaxSlotVicinity_ = 0;
    MySlot_  = 0;
    MySlot1_ = wsnID_;
    CurrentSlotNumber = 0;
    FameSize = 199;
    MyminASlot_ = 0;
    MyMaxASlot_ = 0;

    // bind some variables to be changeable by the TCL script
    bind("MACMethode_", &MACMethode_);
    bind("SWTCL_", &SWTCL_);
    bind("jitterFactor_", &jitterfactor_);
    bind("crypto_delay_", &crypto_delay_);
    bind_time("interval_", &interval_);
    bind_time("Slotinterval_", &Slotinterval_);
    Slotinterval_ = 0;	// this timer valeu delay the transmission to the selected slot. at the begining of each CH all the 				SSU start sending in the first slot

    // if you add some variables here, add them also to tcl/lib/ns-default.tcl
    
    long int rngseed = 0;
    rng_.set_seed(rngseed); // initialize RNG (for JITTER)
}


// this function is called when a command is given to the agent in a
// TCL-script. Simply add your own commands...
int wsnRBCAgent::command(int argc, const char*const* argv) {
    
    if (argc == 2) {        // a command without additional parameter
        
        if (logtarget_ != 0) {
            
            if (strcmp(argv[1], "start-regbc") == 0) {
                // start the regular broadcasting of wsn messages
                // (example.. you may change this to fit your needs, or add
                // additional commands)
                
                running_ = true;    // we want the timer to be rescheduled
                //if (wsnID_==1) 
		BeginCHInterval();      // start transmission at the begining of the CH interval

                return (TCL_OK);    // always return OK if we get until here
            }
            else if (strcmp(argv[1], "stop-regbc") == 0) {
                // stop the regular broadcasting of wsn messages
                
                running_ = false;       // stop the timers
                pkt_timer_.cancel();
                //printf ("%s \n", "A string");
                return (TCL_OK);
            }
            else if (strcmp(argv[1], "dump-rxdb") == 0) {
                // output the contents of the Receive-database to
                // the logtarget
                
                // create a header-line
                sprintf(logtarget_->pt_->buffer(),
                                    "Node %u: RxDB (t: %f)", wsnID_,
                                            Scheduler::instance().clock());
                logtarget_->pt_->dump();    // new line
                
                rxdb_.print(logtarget_);    // and now dump the data
                
                return (TCL_OK);
            }
        
        }   // end if logtarget_ != 0
        else {      // for logging (only change if you know what you're doing)
            fprintf(stdout,
                "Your logtarget is not defined! You will not be able to\n"
                "print or dump databases (e.g., RxDB). Please create\n"
                "a trace file in your tcl script (Node %u).\n", wsnID_);
        }   // end else logtarget
    
    }
    else if (argc == 3) {       // a command with one parameter
        
        if (strcmp(argv[1], "lookup") == 0) {
            // lookup the status of node argv[2] in the RxDB
            u_int32_t against = atoi(argv[2]);
            double lh;

            printf ("My slot =: %d \n", MySlot_);

            debug("\nNode %u: information about node %u (t: %f):\n",
                            wsnID_, against, Scheduler::instance().clock());
            
            lh = rxdb_.lookup(against);
            if(lh >= 0)
                debug("\tRxDB: last heard at %f.\n", lh);
            else
                debug("\tRxDB: Never heard.\n");
            
            return (TCL_OK);
        }
        
        // for logging (only change if you know what you are doing)
        else if (strcmp(argv[1], "log-target") == 0 ||
                    strcmp(argv[1], "tracetarget") == 0) {
            logtarget_ = (Trace*)TclObject::lookup(argv[2]);
            if (logtarget_ == 0) {
                printf("Node %u: logtarget is zero!\n", wsnID_);
                return TCL_ERROR;
            }
            
            return TCL_OK;
        }
    }
    
    // If the command hasn't been processed by wsnRBCAgent::command,
    // call the command() function for the base class
    return (Agent::command(argc, argv));
}


// this function is called by ns2 if a packet has been received by the
// agent (so, don't remove!)
void wsnRBCAgent::recv(Packet* pkt, Handler*) {
    
    // the different header types, we may need to access.
    // for convenience, we use these structs to access them
    struct hdr_cmn *hdrcmn = HDR_CMN(pkt);
    struct hdr_ip *hdrip = HDR_IP(pkt);
    struct hdr_wsn *hdrgen = HDR_wsn(pkt);
    
    if ((u_int32_t)hdrip->daddr() != IP_BROADCAST) {  // check if brdcast mode
        printf("N %u: NOT BROADCAST Packet received!!\n", wsnID_);
        exit(1);
    }
    
    // dispatch between the different functions for evaluation the
    // different message types
    if(hdrcmn->ptype() == PT_wsnRBC) {
        switch(hdrgen->vn_msgtype) {
            case wsnTYPE_REGBC:
                recvRBC(pkt);
                break;
            
            // ! add dispatching for your message types here
            // (if you have added some in wsnrbc_header.h)
            
            default:
                printf("N %u: Invalid wsn packet-type (%d)\n",
                                            wsnID_, hdrgen->vn_msgtype);
                exit(1);
        }
    }
    else {
        // if you also have other (non-wsn) protocols in your simulations,
        // remove this
        printf("N %d: Non-wsn-Packet received (type: %d)\n",
                                                wsnID_, hdrcmn->ptype());
        exit(1);
    }
    
    // Discard the packet
    Packet::free(pkt);
}


// do the processing of an RBC message
// (example, this is not a mandatory function needed by ns2)
void wsnRBCAgent::recvRBC(Packet* pkt) {
    int pktsz;
    u_int32_t senderID;
    double tStamp;
    double XposS, YposS;    // for storing the Sender's coordinates (example)
    
    u_int16_t MaxSlotS, MySlotS, minASlotS, MaxASlotS; 

    // different header access functions
    struct hdr_wsn_rbc *hdr = HDR_wsn_RBC(pkt);
    
    senderID = hdr->rbc_senderID;
    tStamp = hdr->rbc_timestamp;
    XposS = hdr->rbc_posx;
    YposS = hdr->rbc_posy;


    MaxSlotS = hdr->MaxAssignedSlot;
    MySlotS = hdr->MySlot;
    minASlotS = hdr->minAvailableSlots;
    MaxASlotS = hdr->MaxAvailableSlots;
 double trtime = (Scheduler::instance().clock() - tStamp)*1000; // in ms **************************
    //double trtime = (Scheduler::instance().clock() - tStamp); // in ms **************************
    //double trtime = (Scheduler::instance().clock()); // in ms


    // in opposition to printf(), the debug() function only prints messages
    // if you have put "debug" for agents to true in the TCL script
    //debug("Node %u: received packet from %u, trip time %f ms (t: %f)\n", wsnID_, senderID, trtime, tStamp); 
    
//********************************************************************************************************	

// get packet-size of this type

    pktsz = hdr->size();            
   
    char out[100];      // Prepare the output to the Tcl interpreter.
    hdr_ip* hdrip = HDR_IP(pkt);  // IP header for the received packet
    // call the "recv" function defined in your TCL script
    sprintf(out, "%s recv %d %3.1f", name(), 
        hdrip->src_.addr_ >> Address::instance().NodeShift_[1], trtime);
    
    Tcl& tcl = Tcl::instance();
    tcl.eval(out);

    // get my current location
    MobileNode *pnode = (MobileNode*)Node::get_node_by_address(wsnID_);
    pnode->update_position();       // update the position, before using it
    hdr->rbc_posx = pnode->X();     // include current own location
    YposS = pnode->Y();

   
}


// called to reschedule a new broadcast
void wsnRBCAgent::timeout(int) {
    //pkt_timer_.resched(interval_);
    MobileNode *pnode = (MobileNode*)Node::get_node_by_address(wsnID_);
    pnode->update_position();       // update the position, before using it
   // hdr->rbc_posx = pnode->X();     // include current own location
    double YposS = pnode->Y();
   //YposS = rxdb_.lookup(wsnID_);

double trtime = (Scheduler::instance().clock()); // in ms ********************************************

    //rxdb_.GetMySlot(YposS, MaxSlotVicinity_, MySlot_, MyminASlot_, MyMaxASlot_);
    rxdb_.clear();
    BeginCCHInterval();


}


// broadcast an RBC message
// (example, this is not a mandatory function needed by ns2)
void wsnRBCAgent::sendRBC_pkt() {
    
    int pktsz;
    
    Packet* pkt = allocpkt();      // Create a new packet

    // Access the header for the new packet:

    struct hdr_wsn_rbc *hdr = HDR_wsn_RBC(pkt);
    
    // IP broadcast. This is to ensure that every agent receiving the packet
    // actually gets it, even we don't necessarily use IP
    hdr_ip* iph = HDR_IP(pkt);
    iph->daddr() = IP_BROADCAST;
    iph->dport() = iph->sport();
    
    // set some flags in the header (example)
    hdr->rbc_msgtype = wsnTYPE_REGBC;   // (necessary for dispatching!)
                                          // this can be read at reception in
                                          // hdrgen->vn_msgtype
    hdr->rbc_senderID = wsnID_;
    hdr->rbc_timestamp = Scheduler::instance().clock();
    
    // get my current location
    MobileNode *pnode = (MobileNode*)Node::get_node_by_address(wsnID_);
    pnode->update_position();       // update the position, before using it
    hdr->rbc_posx = pnode->X();     // include current own location
    hdr->rbc_posy = pnode->Y();
    
   // MaxSlotVicinity_ = pnode->Y();




    hdr->MaxAssignedSlot   = MaxSlotVicinity_; 
    hdr->MySlot 	   = MySlot_;
    hdr->minAvailableSlots = MyminASlot_;
    hdr->MaxAvailableSlots = MyMaxASlot_; 
// update the list of neighbors
//rxdb_.add_entry(wsnID_, Scheduler::instance().clock(), pnode->X(), pnode->Y(), MaxSlotVicinity_, MySlot_, MyminASlot_, MyMaxASlot_);
    


   
    pktsz = hdr->size();            // get packet-size of this type
    hdr_cmn::access(pkt)->size() = pktsz;   // set it in the simulator
   // printf ("packet size =: %d \n", hdr->size()); 


        
    // if the timers are running, schedule the next packet
    // (else we are stopped, or it was a single-sent packet)

double trtime = (Scheduler::instance().clock()); // in ms ********************************************

debug("Node %u: send packet at time %f ms in slot %u \n", wsnID_, trtime, MySlot_);

Scheduler::instance().schedule(target_, pkt,
                                       crypto_delay_ + JITTER*jitterfactor_);






}

void wsnRBCAgent::BeginCHInterval() {

// selection of the MAC Methode 
switch (MACMethode_) {
case 1 :// CSMA
MySlot_=0; 
Slotinterval_ = 0; 
break;

case 2 :// DS-CSMA MAC
MySlot_ = Random::random() % SWTCL_; 
Slotinterval_ = MySlot_ * 0.001; 
break;

}


// the set of the Slotinterval_
//Slotinterval_ = MySlot_ * 0.001; 


pkt_timer_.resched(interval_);
SlotCounterTm_.resched(Slotinterval_);

	
}

void
wsnRBCAgent::SDMA() {

int  xmod, ymod;

// get the SU's possition
MobileNode *pnode = (MobileNode*)Node::get_node_by_address(wsnID_);
xmod = 	pnode->X();
ymod = pnode->Y();

switch (xmod) {

case 240 :
xmod = 0;
break;

case 245 :
xmod = 60;
break;

case 250:
xmod = 120;
break;

case 255:
xmod = 180;
break;
}

// slot calculation
ymod = (ymod % 600)/10;
MySlot_ = ymod + xmod;

//printf(" %d xmod position= %d ymod position=  %d MySlot %d\n", xmod, ymod, MySlot_);
}
