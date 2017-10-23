import string
import random
import hashlib
import datetime

challenge_example = 'dJf2LKs29Djkfdj3897jfdkjf323719'

def source_generation (challenge=challenge_example, size =30):
    answer = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for x in range(size))
    attempt = challenge + answer
    return attempt, answer

shahash = hashlib.sha256()

def mining():
    attempt,answer = source_generation()
    shahash.update(attempt)
    solution = shahash.hexdigest()
    if solution.startswith('00000'):
        endtime = datetime.datetime.now()
        print solution
        print (endtime - starttime).seconds


starttime = datetime.datetime.now()
for x in range(0,1000000):
    mining()


