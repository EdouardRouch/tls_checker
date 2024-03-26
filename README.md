# TLS Checker

## Description

The `tls_checker.py` script is a tool for checking the TLS configuration of a given host by comparing it to the ANSSI TLS recommandations. 

It connects to the specified host and retrieves useful information about the given TLS server like the supported TLS versions, cipher suites, certificate details and more !

## Installation
1. Clone the repository.
    ```sh
    git clone https://github.com/EdouardRouch/tls_checker
    ```
2. Make sure you have Python 3 installed on your system.
3. Install the required dependencies by running the following command:
   
   ```sh
    pip install -r requirements.txt
   ```
>  ### Linux/macOS
>
>  To allow scapy to have privileges on system's sockets, on Linux you need to give the capability `cap_net_raw` to the Python executable :
>  ```
>  setcap cap_net_raw=eip /usr/bin/pythonX.X>
>  ```
>  Where X.X is the python version you want to use to run the script.
>
>  Alternatively, you could run the script with `sudo` command. Though, use this command with great care as it would give superuser powers to the script.
>  
>  Unfortunately, macOS users have no other choice than to use the latter method.

## Usage

To use the `tls_checker.py` script, follow these steps:

1. Open a terminal and navigate to the directory where the `tls_checker.py` file is located.
2. Run the script with the following command:
   ```
   ./tls_checker.py -h
   ```
   And you will be presented with a helping message that lists the different options.
3. To scan a TLS server, run the script with the following option:
   ```
   ./tls_checker.py -H <host>
   ```
   Replace `<host>` with the URL or IP adress of the given host's TLS server.

   The default port is `443`. To specify another one, use the `-p` option:
   ```
   ./tls_checker.py -H <host> -p <port>
   ```

4. The script will connect to the specified host and display the parameters retrieved during handshake.
5. If you want the tool to automatically review the parameters by comparing them to the [ANSSI TLS recommandations](https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-tls), simply run this command :
   ```
   ./tls_checker.py -H <host> -r ANSSI_TLS_v1-2.json
   ```
   After a few moments a grading and a review of the rules that passed or failed will be displayed.
6. You can generate a JSON encoded version of all the script's results and server's parameters with the `-j` option :
   ```
   ./tls_checker.py -H <host> -j <output_path>
   ```

   Or an HTML version of the report with the `-x` option :
   ```
   ./tls_checker.py -H <host> -x <output_path>
   ```


## Authors

Alexis **CYPRIEN**, Léo **BIREBENT**, Rania **HADDAOUI**, Amina **LARABI**, Édouard **ROUCH**

## Licence

This software is free. You can use it under the terms of GPLv3, see LICENSE.
