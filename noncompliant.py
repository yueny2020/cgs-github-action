#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

# {fact rule=catch-and-rethrow-exception@v1.0 defects=1}
def nested_noncompliant():
    try:
        try_something()
    except KeyError as e:
        try:
            catch_and_try_something()
        # Noncompliant: unnecessary `except` clause.
        except ValueError:
            raise
        raise e
# {/fact}

# {fact rule=aws-logged-credentials@v1.0 defects=1}
def log_credentials_noncompliant():
    import boto3
    import logging
    session = boto3.Session()
    credentials = session.get_credentials()
    credentials = credentials.get_frozen_credentials()
    access_key = credentials.access_key
    secret_key = credentials.secret_key
    # Noncompliant: credentials are written to the logger.
    logging.info('Access key: ', access_key)
    logging.info('secret access key: ', secret_key)
# {/fact}

# {fact rule=log-injection@v1.0 defects=1}
def logging_noncompliant():
    filename = input("Enter a filename: ")
    # Noncompliant: unsanitized input is logged.
    logger.info("Processing %s", filename)
# {/fact}

# {fact rule=sql-injection@v1.0 defects=1}
def execute_query_noncompliant(request):
    import sqlite3
    name = request.GET.get("name")
    query = "SELECT * FROM Users WHERE name = " + name + ";"
    with sqlite3.connect("example.db") as connection:
        cursor = connection.cursor()
        # Noncompliant: user input is used without sanitization.
        cursor.execute(query)
        connection.commit()
        connection.close()
# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def create_session_noncompliant():
    import boto3
    # Noncompliant: uses hardcoded secret access key.
    sample_key = "AjWnyxxxxx45xxxxZxxxX7ZQxxxxYxxx1xYxxxxx"
    boto3.session.Session(aws_secret_access_key=sample_key)
# {/fact}
