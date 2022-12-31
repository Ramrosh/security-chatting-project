package project.utils;

public class Constants {
    /*************************** Algorithms ***************************/

    public static int AES_KEY_SIZE = 256;

    public static int GCM_TAG_LENGTH = 16;

    public static String AES = "AES";

    public static String AES_CIPHER_ALGORITHM = "AES/GCM/NoPadding";

    public static String MAC_ALGORITHM = "HmacSHA256";

    /*************************** Error Messages ***************************/

    public static String ENCRYPTION_ERROR_MESSAGE = "Couldn't encrypt the text :(";

    public static String DECRYPTION_ERROR_MESSAGE = "Couldn't decrypt the text :(";

    public static String AUTHENTICATION_ERROR_MESSAGE = "Oops! MAC is not correct, There is a man in the middle";

    public static String GENERATING_KEY_ERROR_MESSAGE = "Couldn't generate the key :(";

    public static String INCORRECT_MAC_ALGORITHM = "MAC algorithm name is not available";

    public static String INVALID_SECRET_KEY = "The secret key is invalid :(";

    public static String DATABASE_KEY_ERROR = "Couldn't get the user secret key from DB :(";
}
