package project.utils;

import java.io.FileWriter;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import static project.utils.Constants.*;

public class LogFileManager {
    private static final DateFormat dateFormat = new SimpleDateFormat(LOG_FILE_DATE_FORMAT);

    private static final Calendar cal = Calendar.getInstance();

    public static void writeToFile(String phoneNumber, String response, String signature) {
        if(phoneNumber.isEmpty()) return;
        try {
            FileWriter myWriter = new FileWriter(USER_LOG_FILE_PATH(phoneNumber), true);
            myWriter.write("Response from server (" + response + ") Signature (" + signature + ") at: " + dateFormat.format(cal.getTime()) + "\n");
            myWriter.close();
        } catch (IOException e) {
            System.out.println("FileManager: An error occurred.");
            e.printStackTrace();
        }
    }
}