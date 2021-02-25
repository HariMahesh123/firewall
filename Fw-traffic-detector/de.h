/*
  functions declarations, other misc structures in the future.. 
*/

MYSQL* Connect();
bool Insert(MYSQL *con, char *query);
bool Delete(MYSQL *con, char *query);
bool Select(MYSQL *con, char *query);
bool Count(MYSQL *con, char *query, int *count);
void Disconnect(MYSQL *con);

bool processTimeoutInStateMachine(MYSQL *con);

// TCP/UDPport definitions until we find a header fils in linux
#define DNS_PORT_NUM 53

#define  WHITE_LIST 1 
#define   BLACK_LIST 2
#define   STATE_LIST 3

extern bool isNat, isPat;



