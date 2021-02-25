/*******************************************************************************************
 * File Description : This file contains functions for interfacing with MySQL In Memory DB.
 *******************************************************************************************
 *  Author: Atul / Hari
 *******************************************************************************************
 * MySQL In Memory DB table structure.
 * CREATE TABLE StateTable (timeStamp DATETIME NOT NULL,
 *                          srcIP INT UNSIGNED NOT NULL,
 *                          destIP INT UNSIGNED NOT NULL,
 *                          srcPort INT UNSIGNED NOT NULL,
 *                          destPort INT UNSIGNED NOT NULL,
 *                          PRIMARY KEY(srcIP, destIP),
 *                          UNIQUE KEY(srcIP, srcPort)
 *                          ) ENGINE=MEMORY;
 * ref: http://dev.mysql.com/doc/refman/5.5/en/memory-storage-engine.html
 *
 * INSERT INTO StateTable (timeStamp, srcIP, destIP, srcPort, destPort)
 *     values (now(), INET_ATON('1.1.1.1'), INET_ATON('2.2.2.2'), 1111, 2222);
 * SELECT INET_NTOA(srcIP), INET_NTOA(destIP) from StateTable;
 *
 * Dependency on package: apt-get install libmysqlclient-dev
 * When including it in gcc command - use `mysql_config --cflags --libs` see deltaengine.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <mysql.h>
extern double GetPrintTimeStamp();

//static MYSQL *con = NULL;
MYSQL* Connect()
{
        MYSQL *con = mysql_init(NULL);
        printf("\nMySQL client version: %s\n", mysql_get_client_info());
        if (con == NULL)
        {
                printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
                exit(1);
        }
        if (mysql_real_connect(con, "127.0.0.1", "root", "test123", "pi", 0, NULL, 0) == NULL)
        {
                printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
                mysql_close(con);
                exit(1);
        }
        return con;
}

bool Insert(MYSQL *con, char *query)
{
        bool result = true;
        if(con == NULL)
        {
                printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
                exit(1);
        }
        if(mysql_query(con, query) != 0)
        {
                 printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
                /* Try again is case of reconnect */
                if(mysql_query(con,query) != 0)
                {
                        if(mysql_errno(con))
                        {
                                printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
                        }
                        result = false;
                }
        }
        return result;
}

bool Delete(MYSQL *con, char *query)
{
        bool result = true;

        if(con == NULL)
        {
                printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
                exit(1);
        }

        if(mysql_query(con, query) != 0)
        {
                /* Try again is case of reconnect */
                if(mysql_query(con,query) != 0)
                {
                        if(mysql_errno(con))
                        {
                                printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
                        }
                        result = false;
                }
        }
        return result;
}

bool Select(MYSQL *con, char *query)
{
        bool result = true;
        int cnt = 0;
        MYSQL_RES *mysqlResult;
        if(con == NULL)
        {
                printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
                exit(1);
        }

        if(mysql_query(con, query) != 0)
        {
                /* Try again in case of reconnect */
                if(mysql_query(con, query) != 0)
                        result = false;
        }

        if (result)
        {
                mysqlResult = mysql_store_result(con);
                if (mysqlResult == NULL)
                {
                        result = false;
                }
                else
                {
                        int numFields = mysql_num_fields(mysqlResult);
                        MYSQL_ROW rowData;
                        while ((rowData = mysql_fetch_row(mysqlResult)))
                        {
                                for(cnt = 0; cnt < numFields; cnt++)
                                {
                                        // This can be stored in an array.
                                        //printf("\n%s ", rowData[cnt] ? rowData[cnt] : "NULL");
                                }
                        }

                  //      mysql_free_result(mysqlResult);
                }
                mysql_free_result(mysqlResult);
        }
        if(!result)
        {
                if(mysql_errno(con))
                {
                        printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
                }
        }
        return result;
}

bool Count(MYSQL *con, char *query, int *count)
{
        bool result = true;
        bool success = false;
        *count = 0;
        MYSQL_RES *mysqlResult;
        if(con == NULL)
        {
            printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
            exit(1);
        }

        if(mysql_query(con, query) != 0)
        {
                /* Try again in case of reconnect */
                if(mysql_query(con, query) != 0)
                    if(mysql_query(con, query) != 0)
                           result = false;
        }

        if (result)
        {
                mysqlResult = mysql_store_result(con);
                if (mysqlResult == NULL)
                {
                        result = false;
                }
                else
                {
                        MYSQL_ROW rowData;
                        if ((rowData = mysql_fetch_row(mysqlResult)))
                        {
                                *count = atoi(rowData[0]);
                                success = true;
                        }
                 //       mysql_free_result(mysqlResult);
                }
                mysql_free_result(mysqlResult);
        }
        if(!result)
        {
                if(mysql_errno(con))
                {
                        printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
                }
        }
        return success;
}

bool Update(MYSQL *con, char *query)
{
    bool result = true;
    MYSQL_RES *mysqlResult;
    if(con == NULL)
    {
        printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
        exit(1);
    }

    if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
            result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        //else
        //{
         mysql_free_result(mysqlResult);
       // }
    }
    if(!result)
    {
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
    return result;
}

void Disconnect(MYSQL *con)
{
        printf("\nDisconnecting the mysql connection \n");
        mysql_close(con);
}

// Custom methods for specific purposes.
// Let's not spill the MySQL data out of this file.
bool processTimeoutInStateMachine(MYSQL *con)
{
    bool result = true;
    int chkresult = 1;
    MYSQL_RES *mysqlResult;
    char query[300];
    if(con == NULL)
    {
            printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
            exit(1);
    }

    // Fetch all the records which are 5 milliseconds old from State machine.
    sprintf(query, "SELECT * FROM pi.DeltaList WHERE tableType = 'state' AND timeStamp < DATE_SUB(SYSDATE(6), INTERVAL 2000000 MICROSECOND);");

    if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
        result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        else
        {
            MYSQL_ROW rowData;
            while ((rowData = mysql_fetch_row(mysqlResult)))
            {
               // see if the entry in State Table exists in White Table. Most of the case it shouldn't
               // If it did, then remove the the White List and then insert the Black List after incrementing the Rank
               // check for both TCP and UDP protocols
               // Check for Static BL and WL entry here - TODO
               if (isPat)
                     sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %s AND protocol = '%s' AND tableType = 'white';", rowData[1], rowData[5]);
               else if (isNat)
                     sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %s AND dstPort = %s AND protocol = '%s' AND tableType = 'white';", rowData[1], rowData[4], rowData[5]);
                else 
                     sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %s AND dstIP = %s AND dstPort = %s AND protocol = '%s' AND tableType = 'white';", rowData[1], rowData[2], rowData[4], rowData[5]);
               Count(con, query, &chkresult);
#ifdef DEBUG_PRINT
                printf("\n TCP/UDP Check White List table before Inserting into Black List :: %s Checkresult:%d \n", query, chkresult);
#endif
                if (chkresult > 0)
                {
                     //@TODO: Update the query for NAT, PAT & Vanilla.
                     // just delete it from White List TCP protocol
                     sprintf(query, "DELETE FROM pi.DeltaList WHERE srcIP = %s AND dstIP = %s AND dstPort = %s AND protocol = '%s' AND tableType = 'white';", rowData[1], rowData[2],  rowData[4], rowData[5]);
#ifdef DEBUG_PRINT
                     printf("\n TCP/UDP Deleting from White List Before Inserting into Black List :: %s\n", query);
#endif
                     Delete(con, query);
                }

                // TODO - Figure out the Ranking here if the entry is in Black List And ignore inserting it again
                // also check for entry in Black List before re-inserting a new entry . Check for both TCP and UDP here as well.
                // club the above into a separate function..
                // Record exists in State machine. Move to BlackList
                if (isPat)
                     sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %s AND protocol = '%s' AND tableType = 'black';", rowData[1], rowData[5]);
                else if (isNat)
                     sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %s AND dstPort = %s AND protocol = '%s' AND tableType = 'black';", rowData[1], rowData[4], rowData[5]);
                else
                     sprintf(query, "SELECT COUNT(*) FROM pi.DeltaList WHERE srcIP = %s AND dstIP = %s AND dstPort = %s AND protocol = '%s' AND tableType = 'black';", rowData[1], rowData[2], rowData[4], rowData[5]);
                Count(con, query, &chkresult);
#ifdef DEBUG_PRINT
                printf("\n TCP/UDP Check Black List Before Inserting into Black List :: %s Checkresult:%d \n", query, chkresult);
#endif
                if (chkresult == 0)
                {
                      sprintf(query, "INSERT INTO pi.DeltaList (timeStamp, srcIP, dstIP, srcPort, dstPort, protocol, rank, tableType) values (sysdate(6), %s, %s, %s, %s, '%s', 1, 'black');", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5]);
                      Insert(con, query);
          //            printf("\nBlackList::Time: %lf: Invalid traffic: %s\n", GetPrintTimeStamp(), query);
                      #ifdef DEBUG_PRINT
                         printf("\nBlackList::Timedout records processing...");
                         printf("\nBlackList::Invalid traffic: %s\n", query);
                      #endif
                }
                else
                {
                    #ifdef BLACKLIST_RANK
                    if (isPat)
                    {
                        /* Check if the Src IP is in BlackList table, if found do nothing */
                        sprintf(query, "UPDATE pi.DeltaList SET rank = rank + 1 WHERE srcIP = %s AND protocol = '%s' AND tableType = 'black';", rowData[1], rowData[5]);
                    }
                    else if (isNat)
                    {
                        /* Check if the Src IP & Dst Port are in BlackList table, if found do nothing */
                        sprintf(query, "UPDATE pi.DeltaList SET rank = rank + 1 WHERE srcIP = %s AND dstPort = %s AND protocol = '%s' AND tableType = 'black';", rowData[1], rowData[4], rowData[5]);
                    }
                    else
                    {
                        /* Check if the Src IP, Dst IP & Dst Port are in BlackList table, if found do nothing */
                        sprintf(query, "UPDATE pi.DeltaList SET rank = rank + 1 WHERE srcIP = %s AND dstIP = %s AND dstPort = %s AND protocol = '%s' AND tableType = 'black';", rowData[1], rowData[2], rowData[4], rowData[5]);
                    }
                    Update(con, query);
                    #endif
               }

                // Delete from State machine by using the records fetched from Select.
                sprintf(query, "DELETE FROM pi.DeltaList WHERE srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND direction = '%s' AND tableType = 'state';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5], rowData[6]);
           //     printf("\nProcessMonitor:State::Removing record from State: %s", query);
                Delete(con, query);
            }
        //    mysql_free_result(mysqlResult);
        }
        mysql_free_result(mysqlResult);
    }
    if(!result)
    {
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
    return result;
}

// Custom methods for specific purposes.
// Let's not spill the MySQL data out of this file.
bool moveTcpRecordToWhiteListFromStateMachineWithNat(MYSQL *con, struct iphdr  *iph, struct tcphdr *tcph, bool isPat)
{
    bool success = false;
    bool result = true;
    MYSQL_RES *mysqlResult;
    char query[300];
    if(con == NULL)
    {
            printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
            exit(1);
    }

    // Extract IPs from State Table.
    if (isPat)
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp' AND direction = 'wan' AND tableType = 'state';", iph->saddr);
    }
    else
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %u AND protocol = 'tcp' AND direction = 'wan' AND tableType = 'state';", iph->saddr, tcph->dest);
    }
    if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
        result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        else
        {
            MYSQL_ROW rowData;
            while ((rowData = mysql_fetch_row(mysqlResult)))
            {
                // Record exists in State machine. Move to WhiteList
                //sprintf(query, "INSERT INTO pi.DeltaList (timeStamp, srcIP, dstIP, srcPort, dstPort, protocol, tableType) values (sysdate(6), %s, %s, %s, %s, '%s', 'white');", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5]);
                //Insert(con, query);
#ifdef DEBUG_PRINT
                printf("\nWhiteList::Valid traffic: %s\n", query);
#endif
                sprintf(query, "UPDATE pi.DeltaList SET tableType = 'white', timeStamp = now() WHERE srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND direction = '%s' AND tableType = 'state';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5], rowData[6]);
                // Delete from State machine by using the records fetched from Select.
                //sprintf(query, "DELETE FROM pi.DeltaList WHERE srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND direction = '%s' AND tableType = 'state';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5], rowData[6]);
                Update(con, query);
                success = true;
            }
            //mysql_free_result(mysqlResult);
        }
          mysql_free_result(mysqlResult);

    }
    if(!result)
    {
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
    return success;
}


// Custom methods for specific purposes.
// Let's not spill the MySQL data out of this file.
bool moveTcpRecordToWhiteListFromStateMachineWithoutNat(MYSQL *con, struct iphdr  *iph, struct tcphdr *tcph)
{
    bool success = false;
    bool result = true;
    MYSQL_RES *mysqlResult;
    char query[300];
    unsigned int num_records=0;
    if(con == NULL)
    {
            printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
            exit(1);
    }

    // Extract IPs from State Table.
    sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND srcPort = %u AND dstPort = %u AND protocol ='tcp' AND direction = 'wan' AND tableType = 'state';", iph->saddr,iph->daddr, tcph->source, tcph->dest);


    if(mysql_query(con, query))
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query))
        result = false;
 printf("\n MYSQL**** Catch it!!! Query:%s Line:%d\n", query, __LINE__);
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
    }

    if (result)
    {
        num_records = mysql_field_count(con);
         if (!num_records) 
         {
            result = false;
 printf("\n MYSQL**** NUM :%d Query:%s\n", num_records, query);
        }
         else 
         {
          mysqlResult = mysql_store_result(con);
         if (mysqlResult == NULL)
         {
            result = false;
 printf("\n MYSQL******* mysqlresult fails \n");
         }
        else
        {
            MYSQL_ROW rowData;
            while ((rowData = mysql_fetch_row(mysqlResult)))
            {
                // Record exists in State machine. Move to WhiteList
                #ifdef DEBUG_PRINT
                printf("\nWhiteList::Valid traffic: %s\n", query);
                #endif
                 sprintf(query, "UPDATE pi.DeltaList SET tableType = 'white', timeStamp = now() WHERE  srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND direction = '%s' AND tableType = 'state';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5], rowData[6]);
                Update(con, query);
                success = true;
            }
            //mysql_free_result(mysqlResult);
        }
            mysql_free_result(mysqlResult);
      }
    }
    if(!result)
    {
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
    return success;
}


// Custom methods for specific purposes.
// Let's not spill the MySQL data out of this file.
bool moveUdpRecordToWhiteListFromStateMachineWithNat(MYSQL *con, struct iphdr  *iph, struct udphdr *udph, bool isPat)
{
    bool success = false;
    bool result = true;
    MYSQL_RES *mysqlResult;
    char query[300];
    if(con == NULL)
    {
            printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
            exit(1);
    }

    // Extract IPs from State Table.
    if (isPat)
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND protocol ='udp' AND direction = 'wan' AND tableType = 'state';", iph->saddr);
    }
    else
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %u AND protocol ='udp' AND direction = 'wan' AND tableType = 'state';", iph->saddr, udph->dest);
    }

    if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
        result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        else
        {
            MYSQL_ROW rowData;
            while ((rowData = mysql_fetch_row(mysqlResult)))
            {
                // Record exists in State machine. Move to WhiteList
                #ifdef DEBUG_PRINT
                printf("\nWhiteList::Valid traffic: %s\n", query);
                #endif
                // Delete from State machine by using the records fetched from Select.
                sprintf(query, "UPDATE pi.DeltaList SET tableType = 'white', timeStamp = now() WHERE srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND direction = '%s' AND tableType = 'state';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5], rowData[6]);
                Update(con, query);
                success = true;
            }
            //mysql_free_result(mysqlResult);
        }
            mysql_free_result(mysqlResult);

    }
    if(!result)
    {
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
    return success;
}


// Custom methods for specific purposes.
// Let's not spill the MySQL data out of this file.
bool moveUdpRecordToWhiteListFromStateMachineWithoutNat(MYSQL *con, struct iphdr  *iph, struct udphdr *udph)
{
    bool success = false;
    bool result = true;
    MYSQL_RES *mysqlResult;
    char query[300];
    if(con == NULL)
    {
            printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
            exit(1);
    }

    // Extract IPs from State Table.
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND srcPort = %hu AND dstPort = %hu AND protocol ='udp' AND direction = 'wan' AND tableType = 'state';", iph->saddr,iph->daddr, udph->source, udph->dest);

    if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
        result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        else
        {
            MYSQL_ROW rowData;
            while ((rowData = mysql_fetch_row(mysqlResult)))
            {
                // Record exists in State machine. Move to WhiteList
                #ifdef DEBUG_PRINT
                printf("\nWhiteList::Valid traffic: %s\n", query);
                #endif
                sprintf(query, "UPDATE pi.DeltaList SET tableType = 'white', timeStamp = now() WHERE srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND direction = '%s' AND tableType = 'state';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5], rowData[6]);
                Update(con, query);
                success = true;
            }
            //mysql_free_result(mysqlResult);
        }
            mysql_free_result(mysqlResult);

    }
    if(!result)
    {
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
    return success;
}
bool deleteTcpFromStateMachineWithoutNat(MYSQL *con, struct iphdr  *iph, struct tcphdr *tcph)
{
    bool result = true;
    bool success = false;
    MYSQL_RES *mysqlResult;
    char query[300];
    if(con == NULL)
    {
            printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
            exit(1);
    }

    // Extract IPs from State Table
    //TODO - this needs to be fixed for reverse direction when we do do LAN->WAN the direction would be lan.
    sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND srcPort = %hu AND dstPort = %hu AND protocol ='tcp' AND direction = 'wan' AND tableType = 'state';", iph->saddr,iph->daddr, tcph->source, tcph->dest);


    if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
        result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
            printf("\nState::Select query: %s\n", query);
        }
        else
        {
            MYSQL_ROW rowData;
            while ((rowData = mysql_fetch_row(mysqlResult)))
            {
               #ifdef DEBUG_PRINT
                printf("\nDeleting from State Table Without NAT:: %s\n", query);
                #endif
                // Delete from State machine by using the records fetched from Select.
                sprintf(query, "DELETE FROM pi.DeltaList WHERE srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND direction = '%s' AND tableType = 'state';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5], rowData[6]);
                Delete(con, query);
          //      printf("\nState::Delete: %s\n", query);
                success = true;
            }
            //mysql_free_result(mysqlResult);
        }
            mysql_free_result(mysqlResult);
    }
    if(!result)
    {
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
    return success;
}
bool deleteTcpFromStateMachineWithNat(MYSQL *con, struct iphdr  *iph, struct tcphdr *tcph, bool isPat)
{
    bool success = false;
    bool result = true;
    MYSQL_RES *mysqlResult;
    char query[300];
    if(con == NULL)
    {
            printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
            exit(1);
    }

    // Extract IPs from State Table.
    if (isPat)
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp' AND direction = 'wan' AND tableType = 'state';", iph->saddr);
    }
    else
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %u AND protocol = 'tcp' AND direction = 'wan' AND tableType = 'state';", iph->saddr, tcph->dest);
    }
    if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
        result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        else
        {
            MYSQL_ROW rowData;
            while ((rowData = mysql_fetch_row(mysqlResult)))
            {
                #ifdef DEBUG_PRINT
                printf("\nDeleting from State Table:: %s\n", query);
                #endif
                // Delete from State machine by using the records fetched from Select.
                sprintf(query, "DELETE FROM pi.DeltaList WHERE srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND direction = '%s' AND tableType = 'state';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5], rowData[6]);
                Delete(con, query);
                success = true;
            }
            //mysql_free_result(mysqlResult);
        }
            mysql_free_result(mysqlResult);

    }
    if(!result)
    {
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
    return success;
}
// Need to fix these routines when we look at the reverse traffic i.e LAN to WAN as   for now we look at WAN -> LAN only here
bool deleteUdpFromState(MYSQL *con, struct iphdr  *iph, struct udphdr *udph)
{
   bool result = true;
   bool success = false;
   MYSQL_RES *mysqlResult;
    char query[300];

    // Extract IPs from State Table.
    if (isPat)
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'udp' AND direction ='wan' AND tableType = 'state';", iph->saddr);
    }
    else if (isNat) 
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %hu AND protocol = 'udp' AND direction ='wan' AND tableType = 'state';", iph->saddr, udph->dest);
    }
    else 
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND dstIP = %u AND srcPort = %hu AND dstPort = %hu AND protocol = 'udp' AND direction ='wan' AND tableType = 'state';", iph->saddr, iph->daddr, udph->source, udph->dest);
    }
  if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
        result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        else
        {
            MYSQL_ROW rowData;
            while ((rowData = mysql_fetch_row(mysqlResult)))
            {
               #ifdef DEBUG_PRINT
                printf("\nDeleting from State :: %s, File: %s, Line:%d\n", query, __FILE__, __LINE__);
                #endif
                // Delete from Black List by using the records fetched from Select.
                sprintf(query, "DELETE FROM pi.DeltaList WHERE srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND tableType = 'state';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5]);
                Delete(con, query);
           //     printf("\nState::Delete: %s\n", query);
                success = true;
            }
            //mysql_free_result(mysqlResult);
       }
            mysql_free_result(mysqlResult);
    }
    if(!result)
{        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
  return success;


}

bool deleteUdpFromBlackList(MYSQL *con, struct iphdr  *iph, struct udphdr *udph)
{
   bool success = false;
   bool result = true;
   MYSQL_RES *mysqlResult;
    char query[300];

    // Extract IPs from State Table.
    if (isPat)
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'udp' AND tableType = 'black';", iph->saddr);
    }
    else
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %u AND protocol = 'udp' AND tableType = 'black';", iph->saddr, udph->dest);
    }
  if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
        result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        else
        {
            MYSQL_ROW rowData;
            while ((rowData = mysql_fetch_row(mysqlResult)))
            {
               #ifdef DEBUG_PRINT
                printf("\nDeleting from BlackList Table:: %s, File: %s, Line:%d\n", query, __FILE__, __LINE__);
                #endif
                // Delete from Black List by using the records fetched from Select.
                sprintf(query, "DELETE FROM pi.DeltaList WHERE srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND tableType = 'black';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5]);
                Delete(con, query);
                success = true;
            }
            //mysql_free_result(mysqlResult);
       }
            mysql_free_result(mysqlResult);
    }
    if(!result)
    {        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
  return success;
}



bool deleteTcpFromBlackList(MYSQL *con, struct iphdr  *iph, struct tcphdr *tcph)
{
  bool success = false;
  bool result = true;
   MYSQL_RES *mysqlResult;
    char query[300];

    // Extract IPs from State Table.
    if (isPat)
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND protocol = 'tcp' AND tableType = 'black';", iph->saddr);
    }
    else
    {
        sprintf(query, "SELECT * FROM pi.DeltaList WHERE srcIP = %u AND dstPort = %u AND protocol = 'tcp' AND tableType = 'black';", iph->saddr, tcph->dest);
    }
  if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
        result = false;
    }
    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        else
        {
            MYSQL_ROW rowData;
            while ((rowData = mysql_fetch_row(mysqlResult)))
            {
               #ifdef DEBUG_PRINT
                printf("\nDeleting from BlackList Table:: %s, File: %s, Line:%d\n", query, __FILE__, __LINE__);
                #endif
                // Delete from Black List by using the records fetched from Select.
                sprintf(query, "DELETE FROM pi.DeltaList WHERE srcIP = %s AND dstIP = %s AND srcPort = %s AND dstPort = %s AND protocol = '%s' AND tableType = 'black';", rowData[1], rowData[2], rowData[3], rowData[4], rowData[5]);
                Delete(con, query);
                success = true;
            }
            //mysql_free_result(mysqlResult);
        }
            mysql_free_result(mysqlResult);
    }
    if(!result)
    {        
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
  return success;
}

char* readPiMacOptions(MYSQL *con, char* keyword)
{
    bool result = true;
    char query[300];
    MYSQL_RES *mysqlResult;
    char *value;
    sprintf(query, "SELECT HEX(value) FROM pi.PiOptions WHERE keyword = '%s'", keyword);
    if(con == NULL)
    {
        printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
        exit(1);
    }

    if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
            result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        else
        {
            MYSQL_ROW rowData;
            rowData = mysql_fetch_row(mysqlResult);
            value = rowData[0];
            //mysql_free_result(mysqlResult);
        }
            mysql_free_result(mysqlResult);
    }
    if(!result)
    {
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
    return value;
}

char* readPiOptions(MYSQL *con, char* keyword)
{
    bool result = true;
    char query[300];
    MYSQL_RES *mysqlResult;
    char *value;
    sprintf(query, "SELECT value FROM pi.PiOptions WHERE keyword = '%s'", keyword);
    if(con == NULL)
    {
        printf("\nError: %s, File: %s, Line: %d\n", mysql_error(con), __FILE__, __LINE__);
        exit(1);
    }

    if(mysql_query(con, query) != 0)
    {
        /* Try again in case of reconnect */
        if(mysql_query(con, query) != 0)
            result = false;
    }

    if (result)
    {
        mysqlResult = mysql_store_result(con);
        if (mysqlResult == NULL)
        {
            result = false;
        }
        else
        {
            MYSQL_ROW rowData;
            rowData = mysql_fetch_row(mysqlResult);
            value = rowData[0];
            //mysql_free_result(mysqlResult);
        }
            mysql_free_result(mysqlResult);
    }
    if(!result)
    {
        if(mysql_errno(con))
        {
            printf("\nDatabase: mysql_error: %s\nSQL=%s, File: %s, Line: %d\n", mysql_error(con), query, __FILE__, __LINE__);
        }
    }
    return value;
}
