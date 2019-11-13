import math, random 
import smtplib

# Generates OTP 
def generateOtp(): 
    # Declare a digits variable which stores all digits  
    digits = "0123456789"
    otp = "" 
  
   # Length of password can be changed by changing value in range 
    for i in range(6) : 
        otp += digits[math.floor(random.random() * 10)] 
  
    return otp

# Sent OTP to email
def sentOtp():
    otp = generateOtp()
    server = smtplib.SMTP('smtp.gmail.com',587)
    server.ehlo()
    server.starttls()
    server.ehlo()
    sender = 'cs3235otp@gmail.com'
    password = '1q2w#E$R'

    # Receiver will be the login email
    receiver = 'cs3235otp@gmail.com'

    server.login(sender,password)
    msg = "\n" + otp
    server.sendmail(sender,receiver,msg)
    server.close()
    
    return otp
