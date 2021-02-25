/* Includes */
#define _GNU_SOURCE
#include <stdio.h>      /* Input/Output */
#include <sys/time.h>
#include <time.h>
#include <mysql.h>
#include "uthash.h"

#define MAX_BUFFER_POOL_SIZE 100000

typedef enum PktDirection
{
        wan =1,
        lan
}PktDirection;

typedef struct PktInfo
{
        //long connId;
        // required by IPC Arch for successful message processing to be a long
        long timestamp;
        long double srcIP;
        long double dstIP;
        unsigned short srcPort;
        unsigned short dstPort;
        unsigned short protocol;
        unsigned short pktLen;
        PktDirection direction;
} PktInfo;

typedef struct MeasData
{
        long double srcIP;
        unsigned short srcPort;
        long double dstIP;
        unsigned short dstPort;
        unsigned short protocol;
        unsigned int numPktsIn;
        unsigned int numPktsOut;
        unsigned long int numBytesIn;
        unsigned long int numBytesOut;
        long double numBytesSqIn;
        long double numBytesSqOut;
        unsigned long lastTimestampIn;
        unsigned long lastTimestampOut;
        unsigned long totalTimeIn;
        unsigned long totalTimeOut;
        long double totalTimeSqIn;
        long double totalTimeSqOut;

        UT_hash_handle hh;    /* makes the structure hashable*/
}MeasData;

// Define hash table
MeasData *measDataRecs = NULL;
// Define HashKey(srcIp+srcPort)
typedef struct HashKey
{
        long double srcIP;
        unsigned short srcPort;

}HashKey;

// Create a lock for the hash.
pthread_rwlock_t hashLock;

int msgQueueId;
struct PktInfo pktInfoDataWan[MAX_BUFFER_POOL_SIZE];
struct PktInfo pktInfoDataLan[MAX_BUFFER_POOL_SIZE];

void addMeasRecord(PktInfo *pktInfoRec)
{
    #ifdef DEBUG_PRINT
    printf("\nadding record in hash");
    #endif
    MeasData *measDataRec = NULL;

    measDataRec = malloc(sizeof(MeasData));
    measDataRec->srcIP = pktInfoRec->srcIP;
    measDataRec->dstIP = pktInfoRec->dstIP;
    measDataRec->srcPort = pktInfoRec->srcPort;
    measDataRec->dstPort = pktInfoRec->dstPort;
    measDataRec->protocol = pktInfoRec->protocol;

    if (pktInfoRec->direction == wan)
    {
        measDataRec->numPktsIn = 1;
        measDataRec->numBytesIn = pktInfoRec->pktLen;
        measDataRec->numBytesSqIn = (pktInfoRec->pktLen)*(pktInfoRec->pktLen);

        measDataRec->totalTimeIn = 0;
        measDataRec->totalTimeSqIn = 0;
        measDataRec->lastTimestampIn = pktInfoRec->timestamp;

    }
    else
    {
        measDataRec->numPktsOut = 1;
        measDataRec->numBytesOut = pktInfoRec->pktLen;
        measDataRec->numBytesSqOut = (pktInfoRec->pktLen)*(pktInfoRec->pktLen);

        measDataRec->totalTimeOut = 0;
        measDataRec->totalTimeSqOut = 0;
        measDataRec->lastTimestampOut = pktInfoRec->timestamp;
    }
    #ifdef DEBUG_PRINT
        printf("\nmeasRec->protocol = %d", measDataRec->protocol);
        printf("\nmeasRec->numPktsIn = %d", measDataRec->numPktsIn);
        printf("\nmeasRec->numPktsOut = %d", measDataRec->numPktsOut);
        printf("\nmeasRec->numBytesIn = %u",(unsigned int) measDataRec->numBytesIn);
        printf("\nmeasRec->numBytesOut = %u",(unsigned int) measDataRec->numBytesOut);
        printf("\nmeasRec->numBytesSqIn = %u",(unsigned int) measDataRec->numBytesSqIn);
        printf("\nmeasRec->numBytesSqOut = %u",(unsigned int) measDataRec->numBytesSqOut);
        printf("\nmeasRec->lastTimestampIn = %u",(unsigned int) measDataRec->lastTimestampIn);
        printf("\nmeasRec->lastTimestampOut = %u",(unsigned int) measDataRec->lastTimestampOut);
        printf("\nmeasRec->totalTimeIn = %u",(unsigned int) measDataRec->totalTimeIn);
        printf("\nmeasRec->totalTimeOut = %u",(unsigned int) measDataRec->totalTimeOut);
        printf("\nmeasRec->totalTimeSqIn = %u",(unsigned int) measDataRec->totalTimeSqIn);
        printf("\nmeasRec->totalTimeSqOut = %u",(unsigned int) measDataRec->totalTimeSqOut);
    #endif
    //HASH_ADD_INT( measDataRecs, connId, measDataRec );  /* id: name of key field */
    HASH_ADD( hh, measDataRecs, srcIP, sizeof(long double) + sizeof(unsigned short), measDataRec );  /* id: name of key field */
}

MeasData *findMeasRecord(HashKey* hashKey)
{
    #ifdef DEBUG_PRINT
    printf("\nfinding record in hash");
    #endif
    MeasData *measRec = NULL;
    HASH_FIND(hh, measDataRecs, &hashKey->srcIP, sizeof(long double) + sizeof(unsigned short), measRec);
    return measRec;
}

void deleteMeasRec(HashKey* hashKey)
{
    #ifdef DEBUG_PRINT
    printf("\ndeleting record in hash");
    #endif
    MeasData *measRec = findMeasRecord(hashKey);
    HASH_DELETE(hh, measDataRecs, measRec);
    free(measRec);
}

void printHashElements(MYSQL *con)
{
    #ifdef DEBUG_PRINT
    printf("printing hash elements");
    #endif
    char query[200] = "";
    char type[20] = "";
    int result = 0;

    // Generate the file name in appropriate format <SOURCE_NAME>_<DATE>_<TIME>_telemetry.csv
    char filename[30];
    strcpy(filename, "DE_");
    time_t currentDateTime = time(NULL);
    struct tm *timeInfo = localtime(&currentDateTime);
    if (strftime(&filename[3], 20, "%Y%m%d_%H%M", timeInfo)  == 0)
    {
       printf("Error in generating filename");
       exit(1);
    }

    strcpy(&filename[16],"_telemetry.csv");
    printf("filename is %s", filename);

    // Open a file with the above generated format in write mode and populate the telemetry data into the file.
    FILE *filePtr = fopen(filename, "a");
    if (filePtr == NULL)
    {
        printf("Error in opening file");
        exit(1);
    }

    MeasData *measRec = NULL;
    struct in_addr tempAddr;
    char srcAddress[INET_ADDRSTRLEN];
    char dstAddress[INET_ADDRSTRLEN];

    for(measRec=measDataRecs; measRec != NULL; measRec=measRec->hh.next)
    {

        unsigned int AvPktSizeIn = 0;
        unsigned int AvPktSizeOut = 0;
        unsigned int AvTimeIn = 0;
        unsigned int AvTimeOut = 0;
        unsigned short int insidePort = 0;
        unsigned short int outsidePort = 0;
        if (measRec->numPktsIn != 0)
        {
            AvPktSizeIn = (unsigned int) measRec->numBytesIn/measRec->numPktsIn;
            AvTimeIn = (unsigned int) measRec->totalTimeIn/measRec->numPktsIn;
        }
        else
        {
            // Remove this record as there have been no packets in for the last 5 mins.
            // We then move on to the next record so that this does not get printed to csv
            HASH_DELETE(hh, measDataRecs, measRec);
            free(measRec);
            continue;
        }

        if (measRec->numPktsOut != 0)
        {
            AvPktSizeOut = (unsigned int) measRec->numBytesOut/measRec->numPktsOut;
            AvTimeOut = (unsigned int) measRec->totalTimeOut/measRec->numPktsOut;
        }
        tempAddr.s_addr = measRec->srcIP;
        inet_ntop( AF_INET, &tempAddr, srcAddress, sizeof(srcAddress) );

        tempAddr.s_addr = measRec->dstIP;
        inet_ntop( AF_INET, &tempAddr, dstAddress, sizeof(dstAddress));

        // Compute the Source IP / Dest IP behaviour.
        sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %d AND protocol = 'tcp' AND tableType = 'white';", (unsigned int)measRec->srcIP, (unsigned int)measRec->dstIP, measRec->dstPort);
        #ifdef DEBUG_PRINT
        printf("\nTelemetry: Query: %s\n", query);
        #endif
        Count(con, query, &result);
        if (result != 0)
        {
            strcpy(type,"allowed");
        }
        else
        {
            sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND dstPort = %d AND protocol = 'tcp' AND tableType = 'black';", (unsigned int)measRec->srcIP, (unsigned int)measRec->dstIP, measRec->dstPort);
           #ifdef DEBUG_PRINT
           printf("\nTelemetry: Query: %s\n", query);
           #endif
            Count(con, query, &result);
            if (result != 0)
            {
                strcpy(type, "dropped");
            }
            else
            {
                strcpy(type, "unknown");
            }
        }
        insidePort = ((measRec->dstPort & 255)<< 8) | ((measRec->dstPort >> 8)& 255);
        outsidePort = ((measRec->srcPort & 255)<< 8) | ((measRec->srcPort >> 8)& 255);
        fprintf(filePtr, "Type=%s Prot=%d OutsideIP=%s OutsidePort=%d InsideIP=%s InsidePort=%d nPktsIn=%u nBytesIn=%lu AvgPktSizeIn=%u SqrPktSizeIn=%u AvgTimeIn=%u SqrTimeIn=%u nPktsOut=%u nBytesOut=%lu AvgPktSizeOut=%u SqrPktSizeOut=%u AvgTimeOut=%u SqrTimeOut=%u \n ", type, measRec->protocol,
                srcAddress, outsidePort, dstAddress, insidePort, measRec->numPktsIn, measRec->numBytesIn,
                AvPktSizeIn, (unsigned int) measRec->numBytesSqIn, AvTimeIn, (unsigned int) measRec->totalTimeSqIn,measRec->numPktsOut, measRec->numBytesOut,
                AvPktSizeOut, (unsigned int) measRec->numBytesSqOut, AvTimeOut, (unsigned int) measRec->totalTimeSqOut);

        #ifdef DEBUG_PRINT 
        printf("\nmeasRec->srcIP = %s",  srcAddress);
        printf("\nmeasRec->dstIP = %s",  dstAddress);
        printf("\nmeasRec->srcPort = %d",  measRec->srcPort);
        printf("\nmeasRec->dstPort = %d",  measRec->dstPort);
        printf("\nmeasRec->protocol = %d", measRec->protocol);
        printf("\nmeasRec->numPktsIn = %d", measRec->numPktsIn);
        printf("\nmeasRec->numPktsOut = %d", measRec->numPktsOut);
        printf("\nmeasRec->numBytesIn = %u",(unsigned int) measRec->numBytesIn);
        printf("\nmeasRec->numBytesOut = %u",(unsigned int) measRec->numBytesOut);
        printf("\nmeasRec->numBytesSqIn = %u",(unsigned int) measRec->numBytesSqIn);
        printf("\nmeasRec->numBytesSqOut = %u",(unsigned int) measRec->numBytesSqOut);
        printf("\nmeasRec->lastTimestampIn = %u",(unsigned int) measRec->lastTimestampIn);
        printf("\nmeasRec->lastTimestampOut = %u",(unsigned int) measRec->lastTimestampOut);
        printf("\nmeasRec->totalTimeIn = %u",(unsigned int) measRec->totalTimeIn);
        printf("\nmeasRec->totalTimeOut = %u",(unsigned int) measRec->totalTimeOut);
        printf("\nmeasRec->totalTimeSqIn = %u",(unsigned int) measRec->totalTimeSqIn);
        printf("\nmeasRec->totalTimeSqOut = %u",(unsigned int) measRec->totalTimeSqOut);  
        #endif
        // Reset the counters here as they have been printed to the csv.
        measRec->numPktsIn = 0;
        measRec->numBytesIn = 0;
        measRec->numBytesSqIn = 0;

        measRec->totalTimeIn = 0;
        measRec->totalTimeSqIn = 0;
        //measRec->lastTimestampIn = 0;

        measRec->numPktsOut = 0;
        measRec->numBytesOut = 0;
        measRec->numBytesSqOut = 0;

        measRec->totalTimeOut = 0;
        measRec->totalTimeSqOut = 0;
        //measRec->lastTimestampOut = 0;
    }
    fseek(filePtr, 0, SEEK_END);
    if (ftell(filePtr) == 0)
    {
        remove(filename);
    }


    fclose(filePtr);

}


void updateCounters(PktInfo *pktInfoRec, MeasData *measDataRec)
{
     #ifdef DEBUG_PRINT
     printf("\n updating counters");
     #endif
     if (pktInfoRec->direction == wan)
    {
        measDataRec->numPktsIn++;
        measDataRec->numBytesIn+=pktInfoRec->pktLen;
        measDataRec->numBytesSqIn+= (pktInfoRec->pktLen)*(pktInfoRec->pktLen);

        if ((pktInfoRec->timestamp > measDataRec->lastTimestampIn)&& (measDataRec->lastTimestampIn != 0))
        {
            measDataRec->totalTimeIn+=(pktInfoRec->timestamp - measDataRec->lastTimestampIn);
            measDataRec->totalTimeSqIn+=((pktInfoRec->timestamp - measDataRec->lastTimestampIn)*(pktInfoRec->timestamp - measDataRec->lastTimestampIn));
        }
        measDataRec->lastTimestampIn = pktInfoRec->timestamp;
        #ifdef DEBUG_PRINT
        printf("\nupdating wan counters\n");  
        #endif
    }
    else
    {
        measDataRec->numPktsOut++;
        measDataRec->numBytesOut+=pktInfoRec->pktLen;
        measDataRec->numBytesSqOut+= (pktInfoRec->pktLen)*(pktInfoRec->pktLen);
      
        if ((pktInfoRec->timestamp > measDataRec->lastTimestampOut) && (measDataRec->lastTimestampOut != 0))
        {
            measDataRec->totalTimeOut+=(pktInfoRec->timestamp - measDataRec->lastTimestampOut);
            measDataRec->totalTimeSqOut+=((pktInfoRec->timestamp - measDataRec->lastTimestampOut)*(pktInfoRec->timestamp - measDataRec->lastTimestampOut));
        }
        measDataRec->lastTimestampOut = pktInfoRec->timestamp;
        #ifdef DEBUG_PRINT
        printf("\nupdating lan counters\n");  
        #endif
    }
        #ifdef DEBUG_PRINT
        printf("\nmeasRec->protocol = %d", measDataRec->protocol);
        printf("\nmeasRec->numPktsIn = %d", measDataRec->numPktsIn);
        printf("\nmeasRec->numPktsOut = %d", measDataRec->numPktsOut);
        printf("\nmeasRec->numBytesIn = %u",(unsigned int) measDataRec->numBytesIn);
        printf("\nmeasRec->numBytesOut = %u",(unsigned int) measDataRec->numBytesOut);
        printf("\nmeasRec->numBytesSqIn = %u",(unsigned int) measDataRec->numBytesSqIn);
        printf("\nmeasRec->numBytesSqOut = %u",(unsigned int) measDataRec->numBytesSqOut);
        printf("\nmeasRec->lastTimestampIn = %u",(unsigned int) measDataRec->lastTimestampIn);
        printf("\nmeasRec->lastTimestampOut = %u",(unsigned int) measDataRec->lastTimestampOut);
        printf("\nmeasRec->totalTimeIn = %u",(unsigned int) measDataRec->totalTimeIn);
        printf("\nmeasRec->totalTimeOut = %u",(unsigned int) measDataRec->totalTimeOut);
        printf("\nmeasRec->totalTimeSqIn = %u",(unsigned int) measDataRec->totalTimeSqIn);
        printf("\nmeasRec->totalTimeSqOut = %u",(unsigned int) measDataRec->totalTimeSqOut);
        #endif
}

void resetCounters()
{
    #ifdef DEBUG_PRINT
    printf("\n reset counters");
    #endif
    MeasData *measRec = NULL;

    for(measRec=measDataRecs; measRec != NULL; measRec=measRec->hh.next)
    {
        measRec->numPktsIn = 0;
        measRec->numBytesIn = 0;
        measRec->numBytesSqIn = 0;

        measRec->totalTimeIn = 0;
        measRec->totalTimeSqIn = 0;
        //measRec->lastTimestampIn = 0;

        measRec->numPktsOut = 0;
        measRec->numBytesOut = 0;
        measRec->numBytesSqOut = 0;

        measRec->totalTimeOut = 0;
        measRec->totalTimeSqOut = 0;
        //measRec->lastTimestampOut = 0;
    }
}

void generateCsvData()
{

    MYSQL *con = NULL;
    usleep(1000);
    con = Connect();

// This thread will wake up every 5 mins and read the entries from the hash, generate the
// CSV file and then reset the counters in the hash.
    while(1)
    {
        sleep(60);
        // Print the hash element data to csv file if the hash is not empty.
        if (HASH_CNT(hh, measDataRecs) != 0)
        {

            // Take a lock on the hash.
            if (pthread_rwlock_rdlock(&hashLock) != 0)
            {
                printf("can't acquire readlock\n");
                exit(-1);
            }
            // print the hash elements
            printHashElements(con);
            //resetCounters();
            pthread_rwlock_unlock(&hashLock);
        }
    }



}


