# Installation

## 1. Python

The Revocation service was tested with

+ Python version 3.10

If you don't have it installed, please download it from <https://www.python.org/downloads/> and follow the [Python Developer's Guide](https://devguide.python.org/getting-started/).

## 2. Flask

The Revocation service was tested with

+ Flask v. 2.3

and should only be used with Flask v. 2.3 or higher.

To install [Flask](https://flask.palletsprojects.com/en/2.3.x/), please follow the [Installation Guide](https://flask.palletsprojects.com/en/2.3.x/installation/).

## 3. How to run the Revocation service?

To run the Revocation service, please follow these simple steps (some of which may have already been completed when installing Flask) for Linux/macOS or Windows.


1. Clone the Revocation service repository:

    ```shell
    git clone git@github.com:eu-digital-identity-wallet/eudi-srv-statuslist-py.git
    ```

2. Create a `.venv` folder within the cloned repository:

    ```shell
    cd eudi-srv-statuslist-py
    python3 -m venv .venv
    ```

3. Activate the environment:

   Linux/macOS

    ```shell
    . .venv/bin/activate
    ```

    Windows

    ```shell
    . .venv\Scripts\Activate
    ```


4. Install or upgrade _pip_

    ```shell
    python -m pip install --upgrade pip
    ```


5. Install Flask and other dependencies in the virtual environment

    ```shell
    pip install -r app/requirements.txt
    ```

6. Setup .env secrets
   
   -  Add the file app/.venv defining the API_key 

7. Run the Revocation Service

    On the root directory of the clone repository, insert one of the following command lines to run the Revocation Service.

    + Linux/macOS/Windows (on <http://127.0.0.1:5000> or <http://localhost:5000>)

    ```
    flask --app app run
    ```

    + Linux/macOS/Windows (on <http://127.0.0.1:5000> or <http://localhost:5000> with flag debug)

    ```
    flask --app app run --debug
    ```