# Make a request to a web page
import requests
# in python we have build in module to generate a hash
import hashlib
from sys import exit


def request_api_data(query_char):
    """Request data bsed on first 5 query characters"""
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)

    # Here we check if len(query_char) == 5 and if it is a hash, beacuse this is required by our API
    if res.status_code != 200:
        raise RuntimeError(
            f"Error fetching: {res.status_code}, check API and try again")

    return res


def main():

    filename = './passwords.txt'
    passwords_to_check = []

    with open(filename) as f:
        for line in f:
            passwords_to_check.append(line.rstrip())

    for item in passwords_to_check:
        print(pwned_api_check(str(item)))

    exit()


def get_password_leaks_counts(hashes, hash_to_check, actual_password):
    """
        When a password hash with the same first 5 characters is found in the 
        Pwned Passwords repository, the API will respond with an HTTP 200 and 
        include the suffix of every hash beginning with the specified prefix, 
        followed by a count of how many times it appears in the data set.
        Sp how many times this password was hacked.
    """
    my_password_hacked_count = 0

    # The splitlines() method splits a string into a list. The splitting is done at line breaks.
    hashes = (line.split(":") for line in hashes.text.splitlines())

    for h, count in hashes:
        if h == hash_to_check.upper():
            my_password_hacked_count = count
            break

    return f"\nYour password: {actual_password} was hacked {my_password_hacked_count} times."


def pwned_api_check(password):
    """ Check password if it exists in API response """
    # .encode('utf-8') gives us b".." syntax
    encodedPassword = password.encode('utf-8')
    sha1password = hashlib.sha1()
    sha1password.update(encodedPassword)
    sha1password = sha1password.hexdigest()

    first_5_char, tail = sha1password[:5], sha1password[5:]
    # response from API
    response = request_api_data(first_5_char)

    return get_password_leaks_counts(response, tail, password)


if __name__ == '__main__':
    main()
