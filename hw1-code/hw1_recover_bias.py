from audioop import bias
import requests
import config as cfg
from collections import defaultdict




def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"xor given bytes of unequal length. {len(a)=} {len(b)=}"
    return bytes(a ^ b for a, b in zip(a, b))


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def bias_encryption_oracle(pt: bytes) -> bytes:
    res = requests.get(cfg.BIAS_URL, auth=(cfg.usr, cfg.key), params={"pt": pt.hex()})
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def recover_flag() -> bytes:
    flag = bytes()
   
    # TODO: fill in your answer here
 
    message = "000000000000000000"
    flag_temp = []
    bias_dict = defaultdict(int)
    biased_bit = 0


# here we will find the biased bit position
    for i in range(200):

        result = bias_encryption_oracle(message.encode()).hex()
        byte_array = bytearray.fromhex(result)
        for i in range(len(byte_array)):
            bias_dict[str(byte_array[i])+','+str(i)] += 1
        
# here we are storing the most likely value to show up in the biased bit position and the index
    biased_bit = max(bias_dict, key=bias_dict.get).split(',')[1]
    most_likely_val = max(bias_dict, key=bias_dict.get).split(',')[0]
    

    message = ""
    for i in range(int(biased_bit)):
        message += "1"

# now we must uncover the flag using the biased bit position with various message lengths
    while len(message) >= (int(biased_bit)+1) -10:
        bias_dict = defaultdict(int)
        for i in range(20):
            result2 = bias_encryption_oracle(message.encode()).hex()
            byte_arr = bytes.fromhex(result2)
    
            bias_dict[byte_arr[int(biased_bit)]] += 1
        flag_temp.append(max(bias_dict, key=bias_dict.get))
        message = message[1:]
    

   
# here we are XORing the flag we uncovered with the most likely value in the biased bit position
    bytes_of_flag = bytes(flag_temp).hex()
    bytes_flag_arr = [bytes_of_flag[i:i+2] for i in range(0, len(bytes_of_flag), 2)]

    result = ""
    
    for b in bytes_flag_arr:
        xored_val = xor(bytes.fromhex(str(b)), bytes.fromhex(str(most_likely_val).encode().hex()))
        result+=(xored_val.decode())

    return bytes(result.encode())


if __name__ == "__main__":

    try:

        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    flag = recover_flag()
    print(flag.decode())
