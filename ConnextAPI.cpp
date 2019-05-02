#include "ConnextAPI.h"
using namespace std;


std::string ETH_PREAMBLE = "19457468657265756d205369676e6564204d6573736167653a0a3332";

//HTTPClient http;




ConnextAPI::ConnextAPI(std::string url)
{
    http = new HTTPClient();


    web3 = new Web3(web3url.c_str(), "/");
    contract = new Contract(web3, contractAddress.c_str());
    //Local Web3 without SSL
    lweb3 = new LocalWeb3(host_ip, web3_port, contract);

    crypto = new Crypto(web3);
    //todo:this is naughty REMOVE
    Serial.printf("Setting Privatekey\n %s", pk);

    crypto->SetPrivateKey(pk);
}



template <typename T>
std::string ToString(T val)
{
    std::stringstream stream;
    stream << val;
    return stream.str();
}

template <typename T>
T StringToNumber(const std::string &Text)
{
    istringstream ss(Text);
    T result;
    return ss >> result ? result : 0;
}

double convertCharToDouble(const char *aString)
{
    return std::strtod(aString, nullptr);
}

std::string getJsonElementValue(const char *name, const char *json)
{
    cJSON *elem;
    cJSON *root = cJSON_Parse(json);
    //int n = cJSON_GetArraySize(root);

    elem = cJSON_GetObjectItem(root, name);
    if (cJSON_IsString(elem))
    {
        std::string obj = cJSON_Print(elem);
        std::string subobj = obj.substr(1, obj.size() - 2);

        Serial.println((String) "got " + name + " " + subobj.c_str());
        return subobj;
    }
    return cJSON_Print(elem);
}

std::string ConnextAPI::httpGET(const char *endpoint, const char *cookie, bool isJson)
{
    http->begin(endpoint);
    http->addHeader("Cookie", (String)authCookie.c_str());
    http->addHeader("Authorization", "Bearer foo");

    int httpCode = http->GET();
    if (httpCode > 0)
    {
        std::string payload = http->getString().c_str();

        Serial.print((String)payload.c_str());

        return payload;
    }
    http->end();
    return "NOGOOD";
}

std::string ConnextAPI::httpPOST(const char *endpoint, const char *postData, bool isJson, const char *cookie)
{

    HTTPClient http;

    http.begin(endpoint);
    static const char *HEADER_NAMES[] = {"set-cookie"};
    http.collectHeaders(HEADER_NAMES, 1);

    if (isJson == false)
    {
        http.addHeader("Content-Type", "application/x-www-form-urlencoded");
    }
    else
    {
        http.addHeader("Content-Type", "application/json");

        if (strcmp(cookie, "") == 0)
        {

            http.addHeader("Cookie", (String)authCookie.c_str());
        }
        http.addHeader("Authorization", "Bearer foo");
        int httpCode = http.POST(postData);

        if (httpCode > 0)
        {
            String postResult = http.getString();
            Serial.print(postResult);
            if (http.hasHeader("set-cookie"))
            {
                String cookie = http.header("set-cookie");
                std::string cookies = cookie.c_str();
                authCookie = cookies;
                Serial.println(cookie);
            }
            http.end();
            return (std::string)postResult.c_str();
        }
    }
    http.end();
    return "NOGOOD";
}

std::string ConnextAPI::GetChallenge()
{
    std::string encoded = url + "/auth/challenge";
    std::string res = this->httpPOST(encoded.c_str(), "");
    return getJsonElementValue("nonce", res.c_str());
}

std::string ConnextAPI::GetStatus()
{
    std::string encoded = url + "/auth/status";

    http->begin(encoded.c_str());
    Serial.println((String) "cookie being sent " + authCookie.c_str());
    //WTF?
    // std::string res = ConnextAPI::ConnextAPI::httpGET(encoded.c_str(), "");
    std::string res = this->httpGET(encoded.c_str(), "");

    return getJsonElementValue("success", res.c_str());
}

std::string ConnextAPI::AuthResponse(std::string nonce, std::string address, std::string origin, std::string signature)
{
    std::string encoded = url + "/auth/response";

    cJSON *jsonData;
    jsonData = cJSON_CreateObject();
    cJSON_AddItemToObject(jsonData, "nonce", cJSON_CreateString(nonce.c_str()));
    cJSON_AddItemToObject(jsonData, "address", cJSON_CreateString(address.c_str()));
    cJSON_AddItemToObject(jsonData, "origin", cJSON_CreateString(origin.c_str()));
    cJSON_AddItemToObject(jsonData, "signature", cJSON_CreateString(signature.c_str()));

    std::string data = cJSON_PrintUnformatted(jsonData);

    Serial.println((String) "JSON To POST\n" + data.c_str());
    std::string res = this->httpPOST(encoded.c_str(), data.c_str(), true, "  ");

    return res;
}

uint8_t * ConnextAPI::GetAuthHashHex(std::string challenge)
{

    std::string HASH_PREAMBLE = "SpankWallet authentication message:";
    std::string origin = "localhost";

    uint8_t nonceHash[ETHERS_KECCAK256_LENGTH];
    uint8_t originHash[ETHERS_KECCAK256_LENGTH];
    uint8_t authHash[ETHERS_KECCAK256_LENGTH];
    static uint8_t fullHash[ETHERS_KECCAK256_LENGTH];

    Crypto::Keccak256((uint8_t *)challenge.c_str(), challenge.length(), nonceHash);

    Crypto::Keccak256((uint8_t *)origin.c_str(), origin.length(), originHash);

    std::string nonceHexHash = Util::ConvertBytesToHex(nonceHash, ETHERS_KECCAK256_LENGTH);

    std::string originHexHash = Util::ConvertBytesToHex(originHash, ETHERS_KECCAK256_LENGTH);

    std::string authHex = HASH_PREAMBLE + " " + nonceHexHash + " " + originHexHash;

    Crypto::Keccak256((uint8_t *)authHex.c_str(), authHex.length(), authHash);

    std::string authString = Util::ConvertBytesToHex(authHash, ETHERS_KECCAK256_LENGTH);

    authString.erase(0, 2);

    Serial.println((String) "Auth Hash" + authString.c_str());

    std::string fullHex = ETH_PREAMBLE + authString;

    Crypto::Keccak256((uint8_t *)fullHex.c_str(), fullHex.length(), fullHash);

    Serial.println((String) "Full Hex\n" + fullHex.c_str());

    std::string fullHashStr = Util::ConvertBytesToHex(fullHash, ETHERS_KECCAK256_LENGTH);

    Serial.println((String) "Full Hash" + fullHashStr.c_str());


    return fullHash;
}

std::string ConnextAPI::SignHash(uint8_t *hash)
{
    BYTE sigBytes[ETHERS_SIGNATURE_LENGTH];

    Web3 *web3;
    web3 = new Web3("", "");


    crypto->Sign(hash, sigBytes);
    std::string signedMsg = Util::ConvertBytesToHex(sigBytes, 65);
    Serial.println((String) "Full SigMsg\n" + signedMsg.c_str());

    return signedMsg;
}

void ConnextAPI::AuthorizeWithHub()
{
	Serial.println("inside Connext AuthHub");
    std::string challenge = this->GetChallenge();
    uint8_t *fullHash = this->GetAuthHashHex(challenge);

    std::string signedMsg = this->SignHash(fullHash);

    std::string response = this->AuthResponse(challenge, userAddress, "localhost", signedMsg);

    if (strcmp(response.c_str(), "Bad Request") != 0)
    {

        cJSON *json = cJSON_Parse(response.c_str());

        cJSON *token = cJSON_GetObjectItem(json, "token");

        std::string aToken = cJSON_GetStringValue(token);

        Serial.println((String) "Token\n" + aToken.c_str());
    }
    return;
}


signedDepositReq_t ConnextAPI::CreateSignedDeposit(unsignedPayment_t unsignedPayment)
{

    BYTE sigBytes[ETHERS_SIGNATURE_LENGTH];
    //
    double wei = convertCharToDouble(unsignedPayment.amountWei.c_str());

    double token = convertCharToDouble(unsignedPayment.amountToken.c_str());
    //
    std::string amountWei = contract->GenerateBytesForUint(wei);
    std::string amountToken = contract->GenerateBytesForUint(token);

    std::string rawValues = amountToken + amountWei;

    Serial.printf("Raw Deposit Values, \nToken: %s \nWei: %s", amountToken.c_str(), amountWei.c_str());

    uint8_t *valuesHash = (uint8_t *)rawValues.c_str();

    std::string vHash = Crypto::Keccak256(Util::ConvertHexToVector(valuesHash));

    Serial.println((String) "Values Hash:\n" + vHash.c_str());
    //Chop 0x from hash
    vHash.erase(0, 2);

    //Add Preamble To Deposit Hash

    std::string payment = ETH_PREAMBLE + vHash;

    Serial.println(payment.c_str());

    //Hash (Preamble + vHash )
    uint8_t *hashBytes = (uint8_t *)payment.c_str();

    std::string hashString = Crypto::Keccak256(Util::ConvertHexToVector(hashBytes));

    hashString.erase(0, 2);

    Serial.println((String) "Final Hash\n" + hashString.c_str());

    uint8_t fHash[32];

    Util::ConvertHexToBytes(fHash, hashString.c_str(), 32);

    crypto->Sign(fHash, sigBytes);

    std::string sigMsg = Util::ConvertBytesToHex(sigBytes, 65);
    Serial.println(sigMsg.c_str());


      signedDepositReq_t dep =  {
        unsignedPayment,
        sigMsg };
      return dep;
}

std::string ConnextAPI::SendRequestDeposit(signedDepositReq_t deposit, int txCount, int lastThreadUpdateId)
{
    {
        std::string encoded = url + "/channel/" + userAddress + "/request-deposit";

        cJSON *depositBody;
        depositBody = cJSON_CreateObject();

        cJSON_AddItemToObject(depositBody, "depositWei", cJSON_CreateString(deposit.payment.amountWei.c_str()));
        cJSON_AddItemToObject(depositBody, "depositToken", cJSON_CreateString(deposit.payment.amountToken.c_str()));

        cJSON_AddItemToObject(depositBody, "sigUser", cJSON_CreateString(deposit.sigUser.c_str()));
        cJSON_AddItemToObject(depositBody, "lastChanTx", cJSON_CreateNumber(txCount));
        cJSON_AddItemToObject(depositBody, "lastThreadUpdateId", cJSON_CreateNumber(lastThreadUpdateId));

        std::string data = cJSON_PrintUnformatted(depositBody);

        Serial.println(data.c_str());

        std::string res = this->httpPOST(encoded.c_str(), data.c_str(), true, "");

        // cJSON_Delete(depositBody);

        return res;
    }
}

void ConnextAPI::GetChannel()
{
    std::string encoded = url + "/channel/" + userAddress;
    std::string res = this->httpGET(encoded.c_str(), authCookie.c_str());
    //http.end();
    Serial.println((String) "Channel Info:\n" + res.c_str());
}
//FOR USE WITH /Sync/
vector<hubUpdate_t> ConnextAPI::ParseUpdateFromHub(vector<std::string> updates)
{
    // cJSON *root = hubUpdate ? hubUpdate->child : 0;
    vector<hubUpdate_t> updateVector;
    vector<hubUpdate_t> nullVector;

    Serial.println((String) "Parsing Update Vector with " + updateVector.size() + " members");

    for (auto anUpdate : updates)
    {

        cJSON *hubUpdate = cJSON_Parse(anUpdate.c_str());

        std::string status = cJSON_PrintUnformatted(cJSON_GetObjectItem(hubUpdate, "status"));

        cJSON *update;
        cJSON *updatesArray = cJSON_GetObjectItem(hubUpdate, "updates");

        int updateSize = cJSON_GetArraySize(updatesArray);
        Serial.println((String) "There are: " + updateSize + "updates in the response from Hub");
        if (updateSize > 0)
        {
            cJSON_ArrayForEach(update, updatesArray)
            {
                Serial.println((String) "update is an ojb: " + cJSON_IsObject(update));
                cJSON *type = cJSON_GetObjectItem(update, "type");

                cJSON *updateData = cJSON_GetObjectItem(update, "update");

                cJSON *updateArgs = cJSON_GetObjectItem(updateData, "args");
                cJSON *reason = cJSON_GetObjectItem(updateData, "reason");
                cJSON *sigUser = cJSON_GetObjectItem(updateData, "sigUser");
                cJSON *sigHub = cJSON_GetObjectItem(updateData, "sigHub");
                cJSON *txCount = cJSON_GetObjectItem(updateData, "txCount");
                cJSON *createdOn = cJSON_GetObjectItem(updateData, "createdOn");
                cJSON *id = cJSON_GetObjectItem(updateData, "id");

                cJSON *argsSigUser = cJSON_GetObjectItem(updateArgs, "sigUser");
                cJSON *timeout = cJSON_GetObjectItem(updateArgs, "timeout");
                cJSON *depositWeiUser = cJSON_GetObjectItem(updateArgs, "depositWeiUser");
                cJSON *depositWeiHub = cJSON_GetObjectItem(updateArgs, "depositWeiHub");
                cJSON *depositTokenUser = cJSON_GetObjectItem(updateArgs, "depositTokenUser");
                cJSON *depositTokenHub = cJSON_GetObjectItem(updateArgs, "depositTokenHub");

                cJSON *txHash = cJSON_GetObjectItem(updateArgs, "transactionHash");

                char *correctArgSig;
                if (cJSON_IsNull(argsSigUser))
                {
                    correctArgSig = "";
                }
                else
                {
                    correctArgSig = cJSON_GetStringValue(argsSigUser);
                }

                cJSON_IsNumber(timeout);

                double argTimeout = 0;
                if (cJSON_IsNumber(timeout))
                {
                    argTimeout = timeout->valuedouble;
                }

                hubArgs_t args = {
                    correctArgSig,
                    argTimeout,
                    cJSON_GetStringValue(depositWeiHub),
                    cJSON_GetStringValue(depositWeiUser),
                    cJSON_GetStringValue(depositTokenHub),
                    cJSON_GetStringValue(depositTokenUser),
                    cJSON_GetStringValue(txHash)};

                char *correctSig;
                if (cJSON_IsNull(sigUser))
                {
                    correctSig = "";
                }
                else
                {
                    correctSig = cJSON_GetStringValue(sigUser);
                }
                //todo:supress compiler error
                double txCountD = 0;
                if (cJSON_IsNumber(txCount))
                {
                    txCountD = txCount->valuedouble;
                }
                //todo:supress compiler error
                double idD = 0;
                if (cJSON_IsNumber(id))
                {
                    idD = id->valuedouble;
                }
                hubUpdate_t anUpdate = {
                    cJSON_GetStringValue(type),
                    args,
                    cJSON_GetStringValue(reason),
                    correctSig,
                    cJSON_GetStringValue(sigHub),
                    txCountD,
                    cJSON_GetStringValue(createdOn),
                    idD};

                updateVector.push_back(anUpdate);
            }
        }
    }
    return updateVector;
}

unsignedChannelState_t ConnextAPI::ParseChannelStateJSON(cJSON *state)
{

    cJSON *stateUser;
    cJSON *recipient;
    cJSON *txCountChain;
    cJSON *txCountGlobal;
    cJSON *balanceWeiHub;
    cJSON *balanceWeiUser;
    cJSON *balanceTokenHub;
    cJSON *balanceTokenUser;
    cJSON *pendingDepositWeiHub;
    cJSON *pendingDepositWeiUser;
    cJSON *pendingDepositTokenHub;
    cJSON *pendingDepositTokenUser;
    cJSON *pendingWithdrawlWeiHub;
    cJSON *pendingWithdrawlWeiUser;
    cJSON *pendingWithdrawlTokenHub;
    cJSON *pendingWithdrawlTokenUser;
    cJSON *threadCount;
    cJSON *threadRoot;
    cJSON *sigHub;
    cJSON *sigUser;
    cJSON *timeout;
    cJSON *contractAddress;

    cJSON *device = state->child;
    unsignedChannelState_t returnedState;

    while (device)
    {
        Serial.println(cJSON_PrintUnformatted(device));
        stateUser = cJSON_GetObjectItem(state, "user");
        recipient = cJSON_GetObjectItem(state, "recipient");
        txCountChain = cJSON_GetObjectItem(state, "txCountChain");
        txCountGlobal = cJSON_GetObjectItem(state, "txCountGlobal");
        balanceWeiHub = cJSON_GetObjectItem(state, "balanceWeiHub");
        balanceWeiUser = cJSON_GetObjectItem(state, "balanceWeiUser");
        balanceTokenHub = cJSON_GetObjectItem(state, "balanceTokenHub");
        balanceTokenUser = cJSON_GetObjectItem(state, "balanceTokenUser");
        pendingDepositWeiHub = cJSON_GetObjectItem(state, "pendingDepositWeiHub");
        pendingDepositWeiUser = cJSON_GetObjectItem(state, "pendingDepositWeiUser");
        pendingDepositTokenHub = cJSON_GetObjectItem(state, "pendingDepositTokenHub");
        pendingDepositTokenUser = cJSON_GetObjectItem(state, "pendingDepositTokenUser");
        pendingWithdrawlWeiHub = cJSON_GetObjectItem(state, "pendingWithdrawlWeiHub");
        pendingWithdrawlWeiUser = cJSON_GetObjectItem(state, "pendingWithdrawlWeiUser");
        pendingWithdrawlTokenHub = cJSON_GetObjectItem(state, "pendingWithdrawlTokenHub");
        pendingWithdrawlTokenUser = cJSON_GetObjectItem(state, "pendingWithdrawlTokenUser");
        threadCount = cJSON_GetObjectItem(state, "threadCount");
        threadRoot = cJSON_GetObjectItem(state, "threadRoot");
        sigHub = cJSON_GetObjectItem(state, "sigHub");
        sigUser = cJSON_GetObjectItem(state, "sigUser");
        timeout = cJSON_GetObjectItem(state, "timeout");
        contractAddress = cJSON_GetObjectItem(state, "contractAddress");
        device = device->next;

        if (device == 0)
        {
            unsignedChannelState_t unsignedState = {
                cJSON_PrintUnformatted(contractAddress),
                cJSON_PrintUnformatted(stateUser),
                cJSON_PrintUnformatted(recipient),

                cJSON_PrintUnformatted(balanceWeiHub),

                cJSON_PrintUnformatted(balanceWeiUser),
                cJSON_PrintUnformatted(balanceTokenHub),
                cJSON_PrintUnformatted(balanceTokenUser),

                cJSON_PrintUnformatted(pendingDepositWeiHub),
                cJSON_PrintUnformatted(pendingDepositWeiUser),
                cJSON_PrintUnformatted(pendingDepositTokenHub),
                cJSON_PrintUnformatted(pendingDepositTokenUser),

                cJSON_PrintUnformatted(pendingWithdrawlWeiHub),
                cJSON_PrintUnformatted(pendingWithdrawlWeiUser),
                cJSON_PrintUnformatted(pendingWithdrawlTokenHub),
                cJSON_PrintUnformatted(pendingWithdrawlTokenUser),

                int(cJSON_PrintUnformatted(txCountGlobal)),
                int(cJSON_PrintUnformatted(txCountChain)),
                cJSON_PrintUnformatted(threadRoot),
                int(cJSON_PrintUnformatted(threadCount)),
                int(cJSON_PrintUnformatted(timeout))

            };
            cJSON_Delete(stateUser);
            cJSON_Delete(recipient);
            cJSON_Delete(txCountChain);
            cJSON_Delete(txCountGlobal);
            cJSON_Delete(balanceWeiHub);
            cJSON_Delete(balanceWeiUser);
            cJSON_Delete(balanceTokenHub);
            cJSON_Delete(balanceTokenUser);
            cJSON_Delete(pendingDepositWeiHub);
            cJSON_Delete(pendingDepositWeiUser);
            cJSON_Delete(pendingDepositTokenHub);
            cJSON_Delete(pendingDepositTokenUser);
            cJSON_Delete(pendingWithdrawlWeiHub);
            cJSON_Delete(pendingWithdrawlWeiUser);
            cJSON_Delete(pendingWithdrawlTokenHub);
            cJSON_Delete(pendingWithdrawlTokenUser);
            cJSON_Delete(threadCount);
            cJSON_Delete(threadRoot);
            cJSON_Delete(sigHub);
            cJSON_Delete(sigUser);
            cJSON_Delete(timeout);
            cJSON_Delete(contractAddress);
            returnedState = unsignedState;
        }

    }
    return returnedState;
}

unsigned long long ConnextAPI::stringToULL(std::string charStr)
{
    //Remove The Fucking Quotes Fuck Fuupdate.args.ck
    std::string str = (std::string)charStr;

    str.erase(
        remove(str.begin(), str.end(), '\"'),
        str.end());

    unsigned long long ns = strtoull(str.c_str(), (char **)NULL, 10);
    printf("%llu\n", ns);

    return ns;
}

longState_t ConnextAPI::ChannelJSONToState(const char *channelJSON)
{
    //probs too big
    DynamicJsonBuffer jb(2048);
    JsonObject &root = jb.parseObject(channelJSON);

    if (root.success())
    {
        Serial.println("Successful Parse");
    }

    std::vector<std::string> channelKeys = {
        //Balances
        "balanceWeiHub", "balanceWeiUser", "balanceTokenHub", "balanceTokenUser",
        //Wei
        "pendingDepositWeiHub", "pendingDepositWeiUser", "pendingDepositTokenHub", "pendingDepositTokenUser",
        //Withdrawls
        "pendingWithdrawalWeiHub", "pendingWithdrawalWeiUser", "pendingWithdrawalTokenHub", "pendingWithdrawalTokenUser",
        //txCounts
        "txCountGlobal", "txCountChain",
        //threads
        "threadCount", "timeout"};

    int keyLen = channelKeys.size();
    Serial.println((String) "vec has " + keyLen + " members");

    vector<std::string> channelValues;
    for (auto childID : channelKeys)
    {
        const char *childKey = root["state"][childID.c_str()].as<const char *>();
        Serial.printf("Got %s %s \n", childID.c_str(), childKey);
        channelValues.push_back((std::string)childKey);
    }
    vector<unsigned long long> longInOrder;
    for (auto orderedMember : channelValues)
    {
        longInOrder.push_back(this->stringToULL(orderedMember));
    }

    auto hSig = root["state"]["sigHub"].as<char *>();
    auto uSig = root["state"]["sigUser"].as<char *>();

    for (auto member: longInOrder){
        Serial.printf("Member: %llu", member);
    }
    if (uSig == NULL)
    {
        Serial.println("No user sig");

    }

    longState_t state = {
        longInOrder.at(0),
        longInOrder.at(1),
        longInOrder.at(2),
        longInOrder.at(3),
        longInOrder.at(4),
        longInOrder.at(5),
        longInOrder.at(6),
        longInOrder.at(7),
        longInOrder.at(8),
        longInOrder.at(9),
        longInOrder.at(10),
        longInOrder.at(11),
        longInOrder.at(12),
        longInOrder.at(13),
        longInOrder.at(14),
        longInOrder.at(15),
        hSig,
        (uSig == NULL) ? "" : (std::string)uSig,
    };

    return state;
}

longState_t ConnextAPI::ParseChannelStateJSONToLong(cJSON *state)
{

    Serial.println((String) "Free heap b4 JSON\n" + ESP.getFreeHeap());
    longState_t scopedState;
    cJSON *device = state->child;
    while (device)
    {

        cJSON *txCountChain = cJSON_GetObjectItem(state, "txCountChain");
        cJSON *txCountGlobal = cJSON_GetObjectItem(state, "txCountGlobal");
        cJSON *balanceWeiHub = cJSON_GetObjectItem(state, "balanceWeiHub");
        cJSON *balanceWeiUser = cJSON_GetObjectItem(state, "balanceWeiUser");
        cJSON *balanceTokenHub = cJSON_GetObjectItem(state, "balanceTokenHub");
        cJSON *balanceTokenUser = cJSON_GetObjectItem(state, "balanceTokenUser");
        cJSON *pendingDepositWeiHub = cJSON_GetObjectItem(state, "pendingDepositWeiHub");
        cJSON *pendingDepositWeiUser = cJSON_GetObjectItem(state, "pendingDepositWeiUser");
        cJSON *pendingDepositTokenHub = cJSON_GetObjectItem(state, "pendingDepositTokenHub");
        cJSON *pendingDepositTokenUser = cJSON_GetObjectItem(state, "pendingDepositTokenUser");
        cJSON *pendingWithdrawlWeiHub = cJSON_GetObjectItem(state, "pendingWithdrawalWeiHub");
        cJSON *pendingWithdrawlWeiUser = cJSON_GetObjectItem(state, "pendingWithdrawalWeiUser");
        cJSON *pendingWithdrawlTokenHub = cJSON_GetObjectItem(state, "pendingWithdrawalTokenHub");
        cJSON *pendingWithdrawlTokenUser = cJSON_GetObjectItem(state, "pendingWithdrawalTokenUser");
        cJSON *threadCount = cJSON_GetObjectItem(state, "threadCount");

        cJSON *timeout = cJSON_GetObjectItem(state, "timeout");
        device = device->next;
        if (device == 0)
        {

            longState_t unsignedState = {

                ConnextAPI::stringToULL(cJSON_PrintUnformatted(balanceWeiHub)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(balanceWeiUser)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(balanceTokenHub)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(balanceTokenUser)),

                ConnextAPI::stringToULL(cJSON_PrintUnformatted(pendingDepositWeiHub)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(pendingDepositWeiUser)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(pendingDepositTokenHub)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(pendingDepositTokenUser)),

                ConnextAPI::stringToULL(cJSON_PrintUnformatted(pendingWithdrawlWeiHub)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(pendingWithdrawlWeiUser)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(pendingWithdrawlTokenHub)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(pendingWithdrawlTokenUser)),

                ConnextAPI::stringToULL(cJSON_PrintUnformatted(txCountGlobal)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(txCountChain)),

                // ConnextAPI::stringToULL(cJSON_PrintUnformatted(threadRoot)),
                ConnextAPI::stringToULL(cJSON_PrintUnformatted(threadCount)),

                ConnextAPI::stringToULL(cJSON_PrintUnformatted(timeout))

            };
            scopedState = unsignedState;
        }
    }
//    Serial.println((String) "Free heap after JSON\n" + ESP.getFreeHeap());
    return scopedState;
}

std::string ConnextAPI::GetChannelJson(std::string address)
{
    std::string encoded = url + "/channel/" + address;

    std::string res = ConnextAPI::httpGET(encoded.c_str(), "");
    return res;
}

cJSON *ConnextAPI::GetChannelStateJson(cJSON *res)
{
    cJSON *state;
    state = cJSON_GetObjectItem(res, "state");
    cJSON_free(res);

    return state;
}


longState_t ConnextAPI::GetChannelByUserLong(std::string address)
{
    std::string channelState = this->GetChannelJson(userAddress);
    Serial.println((String) "channelState\n" + channelState.c_str());
    longState_t state = this->ChannelJSONToState(channelState.c_str());

    return state;
}

void ConnextAPI::PaymentHistory()
{
    //todo: unimplemented
    std::string encoded = url + "/payments/history/" + userAddress;

    std::string res = this->httpGET(encoded.c_str(), "");

    Serial.println((String) "Payment Info:\n" + res.c_str());
}

vector<std::string> ConnextAPI::Sync(int chanTxCount)
{
    vector<std::string> resVec;
    for (int i = 0; i <= chanTxCount; i++)
    {
        char txNum;

        sprintf(&txNum, "%d", i);
        Serial.println((String) "Getting Hub Sync @ tx" + txNum);
        std::string encoded = url + "/channel/" + userAddress + "/sync?lastChanTx=" + txNum + "&lastThreadUpdateId=0";
        std::string res = this->httpGET(encoded.c_str(), "");

        resVec.push_back(std::string(res));
    }

    return resVec;
}

cJSON *updateToJSON(hubUpdate_t *update)
{

    cJSON *updateJSON;
    updateJSON = cJSON_CreateObject();

    cJSON_AddItemToObject(updateJSON, "lastThreadUpdateId", cJSON_CreateNumber(0));

    cJSON *updates = cJSON_CreateArray();

    cJSON *anUpdate = cJSON_CreateObject();

    cJSON_AddItemToObject(anUpdate, "id", cJSON_CreateNumber(update->id)); //String?
    cJSON_AddItemToObject(anUpdate, "reason", cJSON_CreateString(update->reason));
    cJSON_AddItemToObject(anUpdate, "sigHub", cJSON_CreateString(update->sigHub));
    cJSON_AddItemToObject(anUpdate, "sigUser", cJSON_CreateString(update->sigUser));
    cJSON_AddItemToObject(anUpdate, "txCount", cJSON_CreateNumber(update->txCount));

    Serial.println(cJSON_PrintUnformatted(anUpdate));

    cJSON *args;
    args = cJSON_CreateObject();
    cJSON_AddItemToObject(args, "depositTokenHub", cJSON_CreateString(update->args.depositTokenHub));
    cJSON_AddItemToObject(args, "depositTokenUser", cJSON_CreateString(update->args.depositTokenUser));
    cJSON_AddItemToObject(args, "depositWeiHub", cJSON_CreateString(update->args.depositWeiHub));
    cJSON_AddItemToObject(args, "depositWeiUser", cJSON_CreateString(update->args.depositWeiUser));
    cJSON_AddItemToObject(args, "sigUser", cJSON_CreateString(update->args.sigUser));
    cJSON_AddItemToObject(args, "timeout", cJSON_CreateNumber(update->args.timeout));
    Serial.println(cJSON_PrintUnformatted(args));

    cJSON_AddItemToObject(anUpdate, "args", args);
    cJSON_AddItemToArray(updates, anUpdate);
    cJSON_AddItemToObject(updateJSON, "updates", updates);

    Serial.println(cJSON_PrintUnformatted(updateJSON));

    return updateJSON;
}

std::string ConnextAPI::Update(int updateNum, hubUpdate_t *update)
{
    cJSON *json = updateToJSON(update);

    char txNum;
    sprintf(&txNum, "%d", updateNum);
    Serial.println((String) "Updating Channel @" + txNum);
    std::string encoded = url + "/channel/" + userAddress + "/update";
    Serial.println(encoded.c_str());
    std::string data = cJSON_PrintUnformatted(json);

    //
    Serial.println(data.c_str());
    std::string res = this->httpPOST(encoded.c_str(), data.c_str(), "");
    return res;
}

std::string packedSha3UintArray(vector<uint32_t> input)
{
    vector<uint32_t> *v1 = &input;
    char numstr[32];
    std::string output;
    for (auto itr = v1->begin(); itr != v1->end(); itr++)
    {

        std::stringstream strs;

        strs << std::hex << *itr;
        std::string element = (std::string)strs.str();
//        Serial.printf("This is the std::string pre pack 0x%08x\n sizeof, %i", strs.str(), sizeof(*itr));
        Util::PadForward(&element, 32);
        output += element;
    }
    Serial.printf("this is the std::string from packing %s", output.c_str());
    return output;
}
std::string packedSha3UintArray(vector<uint64_t> input)
{
    vector<uint64_t> *v1 = &input;
    char numstr[32];
    std::string output;
    for (auto itr = v1->begin(); itr != v1->end(); itr++)
    {

        std::stringstream strs;

        strs << std::hex << *itr;
        std::string element = (std::string)strs.str();
//        Serial.printf("This is the std::string pre pack 0x%08x\n sizeof, %i", strs.str(), sizeof(*itr));
        Util::PadForward(&element, 32);
        output += element;
    }
    Serial.printf("this is the std::string from packing %s", output.c_str());
    return output;
}

state_t ConnextAPI::ChannelToState(unsignedChannelState_t channel)
{

    double a = convertCharToDouble(channel.balanceWeiUser);
    Serial.println(a);

    state_t output =
        {
            convertCharToDouble(channel.balanceWeiHub),
            convertCharToDouble(channel.balanceWeiUser),
            convertCharToDouble(channel.balanceTokenHub),
            convertCharToDouble(channel.balanceTokenUser),

            0,
            0,
            0,
            0,

            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            "a",
            "b"};

    return output;
}



state_t ConnextAPI::UpdateToState(hubUpdate_t *update)
{
    Serial.println((String) "Value of TokenPendingUser: " + update->args.depositTokenUser);
    //todo: add threadRoot here instead of setting in ()GenerateStateHash.

    state_t output = {
        0,
        0,
        0,
        0,
        convertCharToDouble(update->args.depositWeiHub),
        0,
        convertCharToDouble(update->args.depositWeiUser),
        0,
        convertCharToDouble(update->args.depositTokenHub),
        0,
        convertCharToDouble(update->args.depositTokenUser),
        0,
        update->txCount,
        1,
        0,
        update->args.timeout};
    return output;
}

longState_t ConnextAPI::UpdateToLongState(hubUpdate_t update, longState_t prevState)
{
    Serial.println((String) "Value of TokenPendingUser: " + update.args.depositTokenUser);


    //todo: add threadRoot here instead of setting in ()GenerateStateHash.
    unsigned long long txCount = (unsigned long long)update.txCount;
    unsigned long long timeout = (unsigned long long)update.args.timeout;
    longState_t output = {
        prevState.weiHub,
        prevState.weiUser,
        prevState.tokenHub,
        prevState.tokenUser,
        stringToULL(update.args.depositWeiHub),
        stringToULL(update.args.depositWeiUser),
        stringToULL(update.args.depositTokenHub),
        stringToULL(update.args.depositTokenUser),
        prevState.pendingWithdrawalHub,
        prevState.pendingWithdrawalUser,
        prevState.pendingTokenWithdrawalHub,
        prevState.pendingTokenWithdrawalUser,
        txCount,
        prevState.txCountChain,
        prevState.threadCount,
        timeout,
        "",
        ""};
    return output;
}

int RPCToInt(const std::string *json)
{
    Serial.println(json->c_str());
    int ret = -1;
    cJSON *root, *value;
    root = cJSON_Parse(json->c_str());
    value = cJSON_GetObjectItem(root, "result");

    Serial.println(cJSON_Print(value));
    if (cJSON_IsString(value))
    {
        ret = strtol(value->valuestring, nullptr, 16);
    }
    cJSON_free(root);
    return ret;
}

std::string ConnextAPI::ApproveTokens(uint32_t aTokens){

    std::string nonceStr = lweb3->EthGetTransactionCount(&userAddress);

    int nonceVal = RPCToInt(&nonceStr);

    std::string p = contract->SetupContractData("approve(address,uint256)", &hubContractAddress, aTokens);

    std::string valueStrThis = "0x00";

    std::string result = lweb3->SendTransaction(nonceVal, gasPriceVal, gasLimitVal, &tokenContract, &valueStrThis, &p);
    Serial.println(result.c_str());

    std::string transactionHash = web3->getString(&result);
    // Serial.println("TX on Etherscan:");
    // Serial.print(ETHERSCAN_TX);
    Serial.printf("Aprove Tokens TX Data:\n %s", p.c_str());
    Serial.println(transactionHash.c_str());

    return transactionHash;
}

std::string ConnextAPI::GenerateSateHash(state_t state)
{

    Serial.println("Generating Hash");

    // std::string p = contract.GenerateBytesForUint(indices.front());
    std::string cAddy = "a8c50098f6e144bf5bae32bdd1ed722e977a0a42";
    //addy user,recepient array
    std::string uAddy = contract->GenerateBytesForAddress(&userAddress);
    std::string rAddy = contract->GenerateBytesForAddress(&userAddress);
    //wei balance array
    vector<uint32_t> balanceVec;
    balanceVec.push_back(state.weiHub);
    balanceVec.push_back(state.weiUser);
    //token balance array;
    vector<uint32_t> tokenBalanceVec;
    tokenBalanceVec.push_back(state.tokenHub);
    tokenBalanceVec.push_back(state.tokenUser);
    //wei withdrawl/deposit
    vector<uint32_t> pendingWei;
    pendingWei.push_back(state.pendingDepositHub);
    pendingWei.push_back(state.pendingWithdrawlHub);
    pendingWei.push_back(state.pendingDepositUser);
    pendingWei.push_back(state.pendingWithdrawlUser);
    //token withdrawl/deposit
    vector<uint32_t> pendingToken;
    pendingToken.push_back(state.pendingTokenDepositHub);
    pendingToken.push_back(state.pendingTokenWithdrawlHub);
    pendingToken.push_back(state.pendingTokenDepositUser);
    pendingToken.push_back(state.pendingTokenWithdrawlUser);

    //txCounts
    vector<uint32_t> txCounts;
    txCounts.push_back(state.txCountGlobal);
    txCounts.push_back(state.txCountChain);
    const char *byteval = "0000000000000000000000000000000000000000000000000000000000000000";

    std::string tCount = contract->GenerateBytesForUint(state.threadCount);
    std::string timeout = contract->GenerateBytesForUint(state.t);

    std::string txUno = contract->GenerateBytesForUint(state.txCountGlobal);
    std::string txDos = contract->GenerateBytesForUint(state.txCountChain);
    double sig = 00;
    std::string userSig = contract->GenerateBytesForUint(sig);

    std::string res = cAddy + uAddy + rAddy + packedSha3UintArray(balanceVec) + packedSha3UintArray(tokenBalanceVec) + packedSha3UintArray(pendingWei) + packedSha3UintArray(pendingToken) + packedSha3UintArray(txCounts) + byteval + userSig + timeout;
    //
    uint8_t *resBytes = (uint8_t *)res.c_str();
    std::string stateHash = Crypto::Keccak256(Util::ConvertHexToVector(resBytes));
    //chop 0x
    stateHash.erase(0, 2);

    std::string prefixedHash = ETH_PREAMBLE + stateHash;

    uint8_t *hashBytes = (uint8_t *)prefixedHash.c_str();
    std::string hashString = Crypto::Keccak256(Util::ConvertHexToVector(hashBytes));

    Serial.println(prefixedHash.c_str());

    Serial.println((String) "Hash is" + hashString.c_str());
    Serial.println(res.c_str());

    return hashString;
}

std::string ConnextAPI::GenerateLongSateHash(longState_t *state, std::string *auserAddress, std::string *recipientAddress)
{

    Serial.println("Generating Hash");

    std::string cAddy = contractAddress.substr(2, contractAddress.size());

    std::string uAddy = contract->GenerateBytesForAddress(auserAddress);
    std::string rAddy = contract->GenerateBytesForAddress(recipientAddress);
    //wei balance array
    vector<uint32_t> balanceVec;
    balanceVec.push_back(state->weiHub);
    balanceVec.push_back(state->weiUser);
    //token balance array;
    vector<uint64_t> tokenBalanceVec;
    tokenBalanceVec.push_back(state->tokenHub);
    tokenBalanceVec.push_back(state->tokenUser);
    //wei withdrawl/deposit
    vector<uint32_t> pendingWei;
    pendingWei.push_back(state->pendingDepositHub);
    pendingWei.push_back(state->pendingWithdrawalHub);
    pendingWei.push_back(state->pendingDepositUser);
    pendingWei.push_back(state->pendingWithdrawalUser);
    //token withdrawl/deposit
    vector<uint64_t> pendingToken;
    pendingToken.push_back(state->pendingTokenDepositHub);
    pendingToken.push_back(state->pendingTokenWithdrawalHub);
    pendingToken.push_back(state->pendingTokenDepositUser);
    pendingToken.push_back(state->pendingTokenWithdrawalUser);

    //txCounts
    vector<uint32_t> txCounts;
    txCounts.push_back(state->txCountGlobal);
    txCounts.push_back(state->txCountChain);
    //default thread shit maybe just forward pad 64

    std::string tCount = contract->GenerateBytesForUint(state->threadCount);
    std::string timeout = contract->GenerateBytesForUint(state->t);

    const char *byteval = "0000000000000000000000000000000000000000000000000000000000000000";

    std::string txUno = contract->GenerateBytesForUint(state->txCountGlobal);
    std::string txDos = contract->GenerateBytesForUint(state->txCountChain);
    double sig = 00;
    std::string userSig = contract->GenerateBytesForUint(sig);
    Serial.printf("Inside Generate, pendingDepositTokenHub\n\n, %llu", state->pendingTokenDepositHub);


    std::string res = cAddy + uAddy + rAddy + packedSha3UintArray(balanceVec) + packedSha3UintArray(tokenBalanceVec) + packedSha3UintArray(pendingWei) + packedSha3UintArray(pendingToken) + packedSha3UintArray(txCounts) + byteval + userSig + timeout;


    uint8_t *resBytes = (uint8_t *)res.c_str();
    vector<uint8_t> resVector = Util::ConvertHexToVector(resBytes);
    std::string stateHash = Crypto::Keccak256(resVector);

    stateHash.erase(0, 2);

    std::string prefixedHash = ETH_PREAMBLE + stateHash;

    uint8_t *hashBytes = (uint8_t *)prefixedHash.c_str();
    vector<uint8_t> hashVector = Util::ConvertHexToVector(hashBytes);

    std::string hashString = Crypto::Keccak256(hashVector);

    Serial.println(prefixedHash.c_str());

    Serial.println((String) "Hash is" + hashString.c_str());
    Serial.println(res.c_str());

    return hashString;
}

std::string stoh(std::string const &in)
{
    std::ostringstream os;

    for (unsigned char const &c : in)
    {
        os << std::hex << std::setprecision(2) << std::setw(2)
           << std::setfill('0') << static_cast<int>(c);
    }

    return os.str();
}


std::string ConnextAPI::UserAuthorizedUpdate(longState_t *state, std::string sigHub)
{
    Serial.printf("UAU SigHub:\n, %s", sigHub.c_str());
    std::string cAddy = "a8c50098f6e144bf5bae32bdd1ed722e977a0a42";
    std::string uAddy = contract->GenerateBytesForAddress(&userAddress);
    std::string rAddy = contract->GenerateBytesForAddress(&userAddress);

    contract->SetPrivateKey(pk);
    std::string recipient = userAddress;
    //wei balance array
    vector<uint32_t> balanceVec;
    balanceVec.push_back(state->weiHub);
    balanceVec.push_back(state->weiUser);
    //token balance array;
    vector<uint32_t> tokenBalanceVec;
    tokenBalanceVec.push_back(state->tokenHub);
    tokenBalanceVec.push_back(state->tokenUser);
    //wei withdrawl/deposit
    vector<uint32_t> pendingWei;
    pendingWei.push_back(state->pendingDepositHub);
    pendingWei.push_back(state->pendingWithdrawalHub);
    pendingWei.push_back(state->pendingDepositUser);
    pendingWei.push_back(state->pendingWithdrawalUser);

    vector<uint32_t> pendingToken;
    pendingToken.push_back(state->pendingTokenDepositHub);
    pendingToken.push_back(state->pendingTokenWithdrawalHub);
    pendingToken.push_back(state->pendingTokenDepositUser);
    pendingToken.push_back(state->pendingTokenWithdrawalUser);

    //txCounts
    vector<uint32_t> txCounts;
    txCounts.push_back(state->txCountGlobal);
    txCounts.push_back(state->txCountChain);

    vector<uint32_t> t;
    t.push_back(state->t);

    vector<uint32_t> ttCount;
    ttCount.push_back(state->threadCount);

    std::string rootBytes = "0000000000000000000000000000000000000000000000000000000000000000";

    if(state->pendingTokenDepositUser > 0){
        Serial.printf("Approving %llu tokens to be spent by hub (from user)", state->pendingTokenDepositUser);

        this->ApproveTokens(pendingToken.at(2));
        vTaskDelay(30000);
    }

    std::string utf8 = stoh(sigHub);

    //append length (84)
    std::string lengthOfSig = Util::ConvertBase(10, 16, ToString(sigHub.length()).c_str());

    Serial.println((String) "lengthofSig\n" + lengthOfSig.length());

    Util::PadForward(&lengthOfSig, 32);

    std::string sigPlusLength = lengthOfSig + utf8;


    //vector<std::string> strUtf8 = Util::ConvertCharStrToVector32()
    //std::string utf8Sig = contract.GenerateBytesForString(&utf8);

    std::string contractBytes = contract->GenerateContractBytes("userAuthorizedUpdate(address,uint256[2],uint256[2],uint256[4],uint256[4],uint256[2],bytes32,uint256,uint256,string)");

    std::string utf8Str = contract->GenerateBytesForString(static_cast<std::string *>(&sigPlusLength));

    Serial.println((String)balanceVec.size() + "\n" + tokenBalanceVec.size() + "\n" + pendingWei.size() + "\n" + pendingToken.size() + "\n" + txCounts.size());

    std::string res = uAddy + packedSha3UintArray(balanceVec) + packedSha3UintArray(tokenBalanceVec) + packedSha3UintArray(pendingWei) + packedSha3UintArray(pendingToken) + packedSha3UintArray(txCounts) + rootBytes + contract->GenerateBytesForUint(ttCount.at(0)) + contract->GenerateBytesForUint(t.at(0));

    int lengthBeforeSig = ((res.length() + 64) / 2);

    //Make this dynamic for longer sigs? they should always be 65bytes
    utf8Str.erase(utf8Str.end() - 2, utf8Str.end());
    //Util::PadForward(&lengthBeforeSig, 64);

    std::string txData = contractBytes + res + contract->GenerateBytesForUint(lengthBeforeSig) + utf8Str;

    ///////////////////////////////////////////////////////////////
    std::string nonceStr = lweb3->EthGetTransactionCount(&userAddress);
    int nonceVal = RPCToInt(&nonceStr);

    unsigned long long gasPriceVal = 22000000000ULL;
    uint32_t gasLimitVal = 6700000;

    std::ostringstream os;

    os << std::hex << std::setfill('0') << std::setw(16) << pendingWei.at(2);

    std::string weiValue = os.str();

    Serial.println((String) "WEI value" + weiValue.c_str());

    std::string zeroWei = "0x00";

    std::string yoloWei = "0x989680";

    Serial.println((String) "UserWei\n" + packedSha3UintArray(balanceVec).c_str());
    Serial.println((String) "ToeknBal\n" + packedSha3UintArray(tokenBalanceVec).c_str());
    Serial.println((String) "penWei\n" + packedSha3UintArray(pendingWei).c_str());
    Serial.println((String) "PendingToken\n" + packedSha3UintArray(pendingToken).c_str());

    vTaskDelay(2000);
    Serial.printf("Free Heap\n%i", xPortGetFreeHeapSize());
    std::string txHex = lweb3->SendTransaction(nonceVal, gasPriceVal, gasLimitVal, &contractAddress, &zeroWei, &txData);

    Serial.printf("LONG Raw Tx Data: \n, %s", txData.c_str());
    return txHex;
}


std::string ConnextAPI::SignState(std::string stateHash)
{
    uint8_t hash[ETHERS_KECCAK256_LENGTH];
    BYTE sigBytes[ETHERS_SIGNATURE_LENGTH];

    Util::ConvertHexToBytes(hash, stateHash.c_str(), stateHash.length());

    crypto->Sign(hash, sigBytes);

    std::string signedMsg = Util::ConvertBytesToHex(sigBytes, 65);
    Serial.println((String) "Full SigMsg\n" + signedMsg.c_str());
    return signedMsg;
}


std::string ConnextAPI::ECRecoverState(longState_t *state, std::string sig)
{

    std::string hash = this->GenerateLongSateHash(state, &userAddress, &userAddress);

    uint8_t hashBytes[32];
    uint8_t sigBytes[ETHERS_SIGNATURE_LENGTH];
    uint8_t pubKey[ETHERS_PUBLICKEY_LENGTH];
    uint8_t recAddress[ETHERS_ADDRESS_LENGTH];

    Util::ConvertHexToBytes(hashBytes, hash.c_str(), 32);
    Util::ConvertHexToBytes(sigBytes, sig.c_str(), ETHERS_SIGNATURE_LENGTH);

    crypto->ECRecover(sigBytes, pubKey, hashBytes);
    crypto->PublicKeyToAddress(pubKey, recAddress);
    Serial.println(Util::ConvertBytesToHex(pubKey, ETHERS_PUBLICKEY_LENGTH).c_str());
    std::string rAddr = Util::ConvertBytesToHex(recAddress, ETHERS_ADDRESS_LENGTH);
    Serial.println((String) "rec address" + rAddr.c_str());
    return rAddr;
}

signedDepositReq_t ConnextAPI::CreateUserDeposit(std::string token, std::string wei)
{
    unsignedPayment_t deposit = {
        token,
        wei};
    signedDepositReq_t signedDep = this->CreateSignedDeposit(deposit);

    return signedDep;
}

hubUpdate_t ConnextAPI::SignUpdateByPosition(int updateId)
{
    hubUpdate_t updateZero = updates.at(updateId);

    Serial.println(updates.at(updateId).sigHub);

    state_t stateZero = this->UpdateToState(&updateZero);

    std::string zeroHash = this->GenerateSateHash(stateZero);

    std::string signedZeroState = this->SignState(zeroHash);

    Serial.println((String)zeroHash.c_str() + "\n" + signedZeroState.c_str());

    hubUpdate_t updateOne = updateZero;
    updateOne.sigUser = (char *)signedZeroState.c_str();

    return updateOne;
}

std::string ConnextAPI::RequestCollateral(std::string user, int lastChannelTx){
    char txNum;
    sprintf(&txNum, "%d", lastChannelTx);
    std::string encoded = url + "/channel/" + userAddress + "/request-collateralization?lastChanTx=" + txNum;

    std::string res = this->httpPOST(encoded.c_str(), "");
    return res;
}
