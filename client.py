import socket
import json

def send_request(sock, request):
    request_str = json.dumps(request)
    sock.sendall((request_str + '\n').encode('utf-8'))
    response = recv_response(sock)
    return response

def recv_response(sock):
    recv_buf = b''
    while b'\n' not in recv_buf:
        data = sock.recv(1024)
        if not data:
            break
        recv_buf += data
    try:
        response = json.loads(recv_buf.decode('utf-8').strip())
    except json.JSONDecodeError:
        response = {"error": "Invalid JSON format"}
    return response

def register(sock):
    username = input("Enter a username: ")
    password = input("Enter a password: ")
    response = send_request(sock, ['REG', username, password])
    print("Response:", response)

def login(sock):
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    response = send_request(sock, ['LOGIN', username, password])
    return response

def get_online_users(sock):
    response = send_request(sock, ['ONLINE'])
    print("Online users:", response)

def send_message(sock, cookie):
    recipient = input("Enter the recipient username: ")
    message = input("Enter your message: ")
    response = send_request(sock, ['SEND', cookie, recipient, message])
    print("Response:", response)

def get_all_messages(sock, cookie):
    user = input("Enter the username to get messages with: ")
    response = send_request(sock, ['GET', cookie, user])
    print("Messages:", response)

def get_new_messages(sock, cookie):
    user = input("Enter the username to get new messages from: ")
    response = send_request(sock, ['NEW', cookie, user])
    print("New messages:", response)

def logout(sock, cookie):
    response = send_request(sock, ['LOGOUT', cookie])
    print("Response:", response)

def main():
    server_address = ('172.16.88.68', 8081)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(server_address)
        
        while True:
            print("Welcome to the chat client!")
            print("1. Register")
            print("2. Login")
            print("3. Check online users")
            print("4. Send a message")
            print("5. Get all messages with a user")
            print("6. Get new messages from a user")
            print("7. Logout")
            print("8. Exit")
            choice = input("Choose an option: ")

            if choice == '1':
                register(sock)

            elif choice == '2':
                response = login(sock)
                if isinstance(response, list) and response[0] == "success":
                    print("Login successful!")
                    cookie = response[1]

                    while True:
                        print("\n--- Menu ---")
                        print("1. Check online users")
                        print("2. Send a message")
                        print("3. Get all messages with a user")
                        print("4. Get new messages from a user")
                        print("5. Logout")
                        sub_choice = input("Choose an option: ")

                        if sub_choice == '1':
                            get_online_users(sock)

                        elif sub_choice == '2':
                            send_message(sock, cookie)

                        elif sub_choice == '3':
                            get_all_messages(sock, cookie)

                        elif sub_choice == '4':
                            get_new_messages(sock, cookie)

                        elif sub_choice == '5':
                            logout(sock, cookie)
                            break

                        else:
                            print("Invalid option, please try again.")

                else:
                    print("Login failed. Please check your username and password.")

            elif choice == '3':
                get_online_users(sock)

            elif choice == '4':
                print("Please login to send a message.")

            elif choice == '5':
                print("Please login to get messages.")

            elif choice == '6':
                print("Please login to get new messages.")

            elif choice == '7':
                print("Please login to logout.")

            elif choice == '8':
                print("Exiting...")
                break

            else:
                print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
