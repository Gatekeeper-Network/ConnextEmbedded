#pragma once
#ifndef ConnextAPI_H
#define ConnextAPI_H

#include <Arduino.h>
#include <Util.h>
#include <Crypto.h>
#include <string>
#include "LCD.h"
#include <cJSON.h>
#include <HTTPClient.h>
#include "LocalWeb3.h"
#include <Web3.h>
#include <Contract.h>

#include "config.h"
#include <iostream>
#include <sstream>
#include <iomanip>

#include <stdlib.h>
#include <stdio.h>
#include <algorithm>
//
#include "LocalWeb3.h"
#include <StreamString.h>


#include "ArduinoJson.h"
//
#include "Contract.h"


using namespace std;

struct unsignedChannelState_t
{
  char* contractAddress;
  char* user;
  char* recipient;

  char* balanceWeiHub;
  char* balanceWeiUser;
  char* balanceTokenHub;
  char* balanceTokenUser;

  char* pendingDepositWeiHub;
  char* pendingDepositWeiUser;
  char* pendingDepositTokenHub;
  char* pendingDepositTokenUser;
  char* pendingWithdrawalWeiHub;
  char* pendingWithdrawalWeiUser;
  char* pendingWithdrawalTokenHub;
  char* pendingWithdrawalTokenUser;
  int txCountGlobal;
  int txCountChain;
  char* threadRoot;
  int threadCount;
  int timeout;

};





struct signedChannelState_t{
  unsignedChannelState_t state;
  string sigUser;
  string sigHub;
};

struct unsignedChannelBN_t
{
  double contractAddress;
  double user;
  double recipient;

  double balanceWeiHub;
  double balanceWeiUser;
  double balanceTokenHub;
  double balanceTokenUser;

  double pendingDepositWeiHub;
  double pendingDepositWeiUser;
  double pendingDepositTokenHub;
  double pendingDepositTokenUser;
  double pendingWithdrawalWeiHub;
  double pendingWithdrawalWeiUser;
  double pendingWithdrawalTokenHub;
  double pendingWithdrawalTokenUser;
  double txCountGlobal;
  double txCountChain;
  double threadRoot;
  double threadCount;
  double timeout;
};




struct unsignedPayment_t
{
  string amountToken;
  string amountWei;

  string toString(){
    return "amountWei: " + amountWei + "amountToken: " + amountToken;
  }
};

struct signedDepositReq_t
{
  unsignedPayment_t payment;
  string sigUser;

  string toString(){
    return payment.toString() + "sigUser: " + sigUser;
  }
};
struct hubArgs_t
{
  char *sigUser;
  double timeout;
  char *depositWeiHub;
  char *depositWeiUser;
  char *depositTokenHub;
  char *depositTokenUser;
  char* transactionHash;
};
struct hubUpdate_t
{
  char* type;
  hubArgs_t args;
  char *reason;
  mutable char *sigUser;
  char *sigHub;
  double txCount;
  char *createdOn;
  double id;
  bool isHubSigned(){
    if(strcmp(sigHub,"")==0){
      return false;
    }else{
      return true;
    }
  }
  bool isUserSigned()
  {
    if (strcmp(sigUser, "") == 0)
    {
      return false;
    }
    else
    {
      return true;
    }
  }
};

// enum ChannelStatus{
//   CS_OPEN = "CS_OPEN",


// }


//Old State Struct UNUSED
struct state_t{
  double weiHub;
  double weiUser;
  double tokenHub;
  double tokenUser;

  double pendingDepositHub;
  double pendingWithdrawlHub;
  double pendingDepositUser;
  double pendingWithdrawlUser;
  //pending Tokens
  double pendingTokenDepositHub;
  double pendingTokenWithdrawlHub;
  double pendingTokenDepositUser;
  double pendingTokenWithdrawlUser;

  //txCounts
  double txCountGlobal;
  double txCountChain;

  //threadRoot
  double threadCount;
  //timeout
  double t;

  mutable string sigHub;
  mutable string sigUser;
};


//Correct State Struct
struct longState_t
{
  //balances
  unsigned long long weiHub;
  unsigned long long weiUser;
  unsigned long long tokenHub;
  unsigned long long tokenUser;
  //deposits
  unsigned long long pendingDepositHub;
  unsigned long long pendingDepositUser;
  unsigned long long pendingTokenDepositHub;
  unsigned long long pendingTokenDepositUser;
  //withdrawls
  unsigned long long pendingWithdrawalHub;
  unsigned long long pendingWithdrawalUser;
  unsigned long long pendingTokenWithdrawalHub;
  unsigned long long pendingTokenWithdrawalUser;
  //txCounts
  unsigned long long txCountGlobal;
  unsigned long long txCountChain;
  //threadRoot
  unsigned long long threadCount;
  //timeout
  unsigned long long t;
  mutable string sigHub;
  mutable string sigUser;
};

//UNUSED
enum ChannelStatus {
  CS_OPEN = 'CS_OPEN',
  CS_CHANNEL_DISPUTE = 'CS_CHANNEL_DISPUTE',
  CS_THREAD_DISPUTE = 'CS_THREAD_DISPUTE',
};



class ConnextAPI
{
  private:

    LocalWeb3 *lweb3;
    Web3 *web3;

    Contract *contract;
    //abstract alcd
    Crypto *crypto;

    HTTPClient *http;
    //API Class Variables
    std::string authToken;
    std::string authCookie;
    //State Storage Variable
    vector<hubUpdate_t> updates;

  public:

    ConnextAPI(string url);
    //create new challenge
    std::string GetChallenge();
    //get challenge string
    std::string GetStatus();
    //Get challenge bytes pointer
    std::string AuthResponse(string nonce, string address, string origin, string signature);
    //get the challenge Hash
    void AuthorizeWithHub();
    std::string GetAuthHex();
    uint8_t* GetAuthHashHex(string challenge);
    std::string SignHash(uint8_t*);
    void StoreAuthToken(string authResponse);
    void GetChannel();
    std::string SendRequestDeposit(signedDepositReq_t depositReq, int txCount, int lastThreadUpdateId);
    //Remove
    vector<string> Sync(int chanTxCount);
    signedDepositReq_t CreateSignedDeposit(unsignedPayment_t unsignedPayment);
    unsignedChannelState_t ParseChannelStateJSON(cJSON* jsonState);
    // void SyncAndParse();
    cJSON * ParseJsonFromHub(cJSON *state);
    static vector<hubUpdate_t> ParseUpdateFromHub(vector<string> updates);
    unsignedChannelState_t GetChannelByUser(string);

    std::string GenerateSateHash(state_t);

    std::string Update(int updateNum, hubUpdate_t *update);


    std::string SignState(string stateHash);
    state_t UpdateToState(hubUpdate_t *update);
    state_t ChannelToState(unsignedChannelState_t channel);



    longState_t UpdateToLongState(hubUpdate_t update, longState_t prevState = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "", ""});

    std::string GenerateLongSateHash(longState_t *state, string *userAddress, string *recipientAddress);

    longState_t ParseChannelStateJSONToLong(cJSON *state);

    longState_t GetChannelByUserLong(string address);

    void PaymentHistory();

    std::string httpGET(const char *endpoint, const char *cookie, bool isJson = true);





    std::string GetChannelJson(string address);

    std::string httpPOST(const char *endpoint, const char *postData, bool isJson = true, const char *cookie = "");

    unsigned long long stringToULL(string charStr);

    cJSON *GetChannelStateJson(cJSON *res);

    longState_t ChannelJSONToState(const char *channelJSON);

    std::string ECRecoverState(longState_t *state, string sig);

    std::string UserAuthorizedUpdate(longState_t *state, string sigHub);

    //todo:remove


    signedDepositReq_t CreateUserDeposit(string tokenAmount, string weiAmount);

    void ConfirmPending(int updateId);

    bool AuthWithHubAndConfirm();

    hubUpdate_t SignUpdateByPosition(int updateId);

    std::string RequestCollateral(string user, int lastChannelTx);

    std::string ApproveTokens(uint32_t aTokens);


};

#endif
