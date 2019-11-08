import math, random 
import smtplib

# Generates OTP 
def generateOTP() : 
    # Declare a digits variable which stores all digits  
    digits = "0123456789"
    OTP = "" 
  
   # Length of password can be changed by changing value in range 
    for i in range(6) : 
        OTP += digits[math.floor(random.random() * 10)] 
  
    return OTP

if __name__ == "__main__" : 
    OTP = generateOTP()
    server = smtplib.SMTP('smtp.gmail.com',587)
    server.ehlo()
    server.starttls()
    server.ehlo()
    sender = 'cs3235otp@gmail.com'
    password = '1q2w#E$R'

    # Receiver will be the login email
    receiver = ''

    server.login(sender,password)
    msg = "\n" + OTP
    server.sendmail(sender,receiver,msg)
    server.close()

    print("Enter received OTP: ")
    enteredOTP = input()

    if OTP == enteredOTP:
        print("Success")
    else:
        print("Failed")
