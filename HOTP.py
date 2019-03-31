#A programme that computes a 6 digits OTP value N times for user authentication
import logging, verboselogs
from Crypto.Hash import HMAC, SHA1

#logger = verboselogs.VerboseLogger('demo')
#logger.addHandler(logging.StreamHandler())
#logger.setLevel(logging.INFO)


secret = b'123456789abcdef0123456789abcdef0'


trial = input("How many times do you want to compute an OTP: ")                                          #Function to display OTP
x = 0                                                               #Used to regulate number of trials
while x<trial:
        counter = input("Enter the counter vaue: ")                     #Enter the counter value required
        HS = HMAC.new(secret, digestmod=SHA1)
        hashbyte = str.encode(str(counter))
        HS = HS.update(hashbyte)
       # HS = HS
        HS = HS.hexdigest()
        print("The hash value is:", HS)                                 #Hash value

        # Obtain the last 4 bits value of the hash
        offset = HS[39]
        offset = int(offset,16)
        print ("The offset value is:", offset)
        offset = offset * 2                                             #Position of offset for hex representation in 4 bits each

        snum = HS[offset: (offset + 8)]                                 #truncation of the hash message

        snumbin = bin(int(snum, 16))[2:].zfill(32)                      #Transform the hexadecimal to binary
        Snumtruncate = snumbin[1:]                                      #Returns the last 31 bits value
        snumhex = hex(int(Snumtruncate,2))                              #Conversion of last 31 bits to Hexadecimal
        print("The snum value is:", snumhex)
        digitvalue = int(Snumtruncate, 2)                                #Generate a digit value in integer
        otp_value = digitvalue % (10**6)                                 #Compute OTP value
        print("The otp value is:", otp_value)

        x +=1
#End of programme

#If the –verbose switch is used, intermediate calculations should be printed to the screen. Using the example from the slides, a sample run would look like:
#./hotpGen –c 1885 –verbose


