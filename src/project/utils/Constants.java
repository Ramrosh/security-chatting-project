package project.utils;

public class Constants {

    /*************************** Algorithms ***************************/

    public static int AES_KEY_SIZE = 256;

    public static int GCM_TAG_LENGTH = 16;

    public static String AES = "AES";

    public static String AES_CIPHER_ALGORITHM = "AES/GCM/NoPadding";

    public static String MAC_ALGORITHM = "HmacSHA256";

    public static int RSA_KEY_SIZE = 4096;

    public static final String RSA = "RSA";

    public static final String RSA_CIPHER_ALGORITHM = "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING";

    /*************************** Error Messages ***************************/

    public static String RSA_ENCRYPTION_ERROR_MESSAGE = "(RSA) Couldn't encrypt the text :(";

    public static String RSA_DECRYPTION_ERROR_MESSAGE = "(RSA) Couldn't decrypt the text :(";

    public static String AES_ENCRYPTION_ERROR_MESSAGE = "(AES) Couldn't encrypt the text :(";

    public static String AES_DECRYPTION_ERROR_MESSAGE = "(AES) Couldn't decrypt the text :(";

    public static String AUTHENTICATION_ERROR_MESSAGE = "Oops! MAC is not correct, There is a man in the middle";

    public static String GENERATING_KEY_ERROR_MESSAGE = "Couldn't generate the key :(";

    public static String INCORRECT_MAC_ALGORITHM = "MAC algorithm name is not available";

    public static String INVALID_SECRET_KEY = "The secret key is invalid :(";

    public static String DATABASE_KEY_ERROR = "Couldn't get the user secret key from DB :(";

    public static String INIT_SERVER_PUBLIC_ERROR_MESSAGE = "Cannot read the server public key :(";

    public static String INIT_SERVER_PRIVATE_ERROR_MESSAGE = "Cannot read the server private key :(";

    public static String HANDSHAKE_ERROR_MESSAGE = "Handshake process failed :(";

    public static String CREATE_DIGITAL_SIGNATURE_ERROR_MESSAGE = "Cannot create digital signature :(";

    public static String VERIFY_DIGITAL_SIGNATURE_ERROR_MESSAGE = "Cannot verify digital signature :(";

    /*************************** Others ***************************/

    // FIXME Change this path to your own project path
    public static String PROJECT_FOLDER_PATH = "F:/Programming/Java/security_chatting_project/fifth_stage_v1/fifth_stage";

    public static String SERVER_PUBLIC_KEY_FILE = "public.key";

    public static String SIGNING_ALGORITHM = "SHA256withRSA";

    public static String SERVER_PRIVATE_KEY_FILE = "private.key";

    public static String KEY_FOLDER_PATH = PROJECT_FOLDER_PATH + "/src/project/keys/";

    public static String CERTIFICATE_FOLDER_PATH = PROJECT_FOLDER_PATH + "/src/project/certificates/";

    public static String REQUEST_PUBLIC_KEY_MESSAGE = "Can I have your public key?";

    public static String REQUEST_DIGITAL_SIGNATURE_MESSAGE = "Can I have your digital signature?";

    public static final String CLIENT_CSR_MESSAGE = "client csr";

    public static final String SERVER_CSR_MESSAGE = "server csr";

    public static final String SESSION_KEY_ACCEPTED = "The Session key accepted";

    public static String CA_PUBLIC_KEY_FILE = "ca_public.key";

    public static String CA_PRIVATE_KEY_FILE = "ca_private.key";

    public static String SERVER_CERTIFICATE_FILE = "certificate.cer";

    public static String USER_PUBLIC_KEY_PATH(String phoneNumber) {
        return phoneNumber + "_public.key";
    }

    public static String USER_PRIVATE_KEY_PATH(String phoneNumber) {
        return phoneNumber + "_private.key";
    }

    public static String CLIENT_CERTIFICATE_PATH(String phoneNumber) {
        return phoneNumber + "_certificate.cer";
    }
}
