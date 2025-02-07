#########################
#### PASSWORD EXTEND ####
#########################

def password_extend(message, password):
    return password * (len(message) // len(password)) + password[:(len(message) % len(password))]


##########################
#### PASSWORD SLICING ####
##########################

def password_slicing(message, password):
    return password[:(len(message))]

######################
#### TEXT CLEANUP ####
######################

def text_cleanup(text):
    return text.replace(" ", "").upper()

#############################
#### PASSWORD PROCESSING ####
#############################

def password_processing(message, password):
    return password_slicing(message, password) if len(message) < len(password) else password_extend(message, password)


####################
#### ENCRYPTION ####
####################

def encryption(message, password):
    message = text_cleanup(message)
    password = text_cleanup(password)
    cipher = ""
    processed_password = password_processing(message, password)
    for m, p in zip(message, processed_password):
        value1 = ((ord(m) - ord('A')) + (ord(p) - ord('A'))) % 26
        generated_letter = chr(value1 + ord('A'))
        cipher += generated_letter
    return cipher


#####################
#### DENCRYPTION ####
#####################

def decryption(ciphered_text, password):
    message = text_cleanup(message)
    password = text_cleanup(password)
    decrypted_text = ""
    processed_password = password_processing(ciphered_text, password)
    for d, p in zip(ciphered_text, processed_password):
        value1 = ((ord(d) - ord('A')) - (ord(p) - ord('A')) + 26) % 26
        generated_letter = chr(value1 + ord('A'))
        decrypted_text += generated_letter
    return decrypted_text