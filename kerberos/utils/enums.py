from enum import Enum

class RequestEnums(Enum): #client -> server
    #Auth server
    CLIENT_REGISTRATION = 1024 #client registration
    SERVER_REGISTRATION = 1025 #server registration (NOTE: BONUS)
    SERVER_LIST = 1026 #list of all server (NOTE: BONUS)
    SYMMETRY_KEY = 1027 #symmetry key
    
    #MSG server
    DELIVER_SYMMETRY_KEY = 1028 #deliver symmetry key to server
    MESSAGE_TO_SERVER = 1029 #send message
    
class Response(Enum): #server -> client
    #Auth server
    REGISTRATION_SUCCESS = 1600 #client registration
    REGISTRATION_FAILED = 1601 #server registration
    SERVER_LIST = 1602 #list of all server
    SYMMETRY_KEY = 1603 #symmetry key
    
    #MSG server
    SERVER_DELIVER_SYMMETRY_KEY_ACCEPT = 1604 #server accept the given symmetric key
    SERVER_MESSAGE_RECIEVED_SUCCESSFULLY = 1605 #server approve that message reached its destination
    SERVER_GENERAL_ERROR = 1609 #general error occured at the msg server