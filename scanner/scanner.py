import sys
from sqlmap import sqlmap

print("URL:")
url = input()  # Target URL.

answers = {
    # got a 302 redirect to '...'. Do you want to follow? [Y/n]
    "follow": "y",
    # do you want to normalize crawling results [Y/n]
    "normalize crawling results": "y",
    # do you want to store crawling results to a temporary file for eventual further processing with other tools [y/N]
    "store git crawling results": "y",
    # it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests?
    "reduce": "y",
    # it looks like the back-end DBMS is '...'. Do you want to skip test payloads specific for other DBMSes? [Y/n]
    "other DBMSes": "y",
    # for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]
    "remaining tests": "y",
    # '...' parameter '...' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
    "keep testing": "n",
    # do you want to exploit this SQL injection? [Y/n]
    "exploit": "y",
    # SQL injection vulnerability has already been detected against '...'. Do you want to skip further tests involving it? [Y/n]
    "skip further tests": "y",
    # please enter number of threads? [Enter for 1 (current)]
    "threads": "1",
    # there were multiple injection points, please select the one to use for following injections
    "multiple injection points": "0"
}

enumeration_options = {
    # Enumerate back-end database management system databases.
    # Valid: True or False
    "getDbs": True,
    # Enumerate back-end database management system database tables.
    # Optional: db
    # Valid: True or False
    "getTables": True,
    # Enumerate back-end database management system database table columns.
    # Optional: db, tbl, col
    # Valid: True or False
    "getColumns": True
}

general_options = {
    # Never ask for user input, use the default behaviour.
    # Valid: True or False
    "batch": True,
    # Parse and test forms on target URL.
    # Valid: True or False
    "forms": True,
    # Redump entries having unknown character marker (?).
    # Valid: True or False
    "repair": True,
    # Crawl the website starting from the target URL.
    # Valid: integer
    # Default: 0
    "crawlDepth": 2,
    # Set predefined answers (e.g. "quit=N,follow=N").
    "answers": answers,
    # Custom output directory path.
    "outputDir": sys.path[1]
}

detection_options = {
    # Level of tests to perform.
    # The higher the value is, the higher the number of HTTP(s) requests are
    # as well as the better chances to detect a tricky SQL injection.
    # Valid: Integer between 1 and 5
    # Default: 1
    "level": 5,
    # Risk of tests to perform.
    # Note: boolean-based blind SQL injection tests with AND are considered
    # risk 1, with OR are considered risk 3.
    # Valid: Integer between 1 and 3
    # Default: 1
    "risk": 3
}

def write_options(file, options, tag):
    file.write("%s\n" % tag)
    for option in options:
        value = options[option]
        if isinstance(value, dict):
            d = dict(value)
            answers_list = list()
            for pair in d.items():
                answer = "%s=%s" % (pair[0], pair[1])
                answers_list.append(answer)
            value = "\"{}\"".format(','.join(answers_list))
        file.write("%s = %s\n" % (option, value))


with open('config.ini', 'w') as file:
    write_options(file, {"url": url}, "[Target]")
    write_options(file, enumeration_options, "[Enumeration]")
    write_options(file, general_options, "[General]")
    write_options(file, detection_options, "[Detection]")

sys.argv = ["-cconfig.ini"]
sqlmap.main()
