package project;

import org.jetbrains.annotations.NotNull;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;

public class DBConnector {

    public static void main(String[] args) {
        connect();
    }

    public static Connection connect() {
        String MySQLURL = "jdbc:mysql://127.0.0.1:3306/chat-app";
        String databaseUserName = "root";
        String databasePassword = "";
        Connection connection = null;
        try {
            connection = DriverManager.getConnection(MySQLURL, databaseUserName, databasePassword);

        } catch (Exception e) {
            e.printStackTrace();
        }
        if (connection != null) {
            System.out.println("Database connection is successful !!!!");
            return connection;
        }
        return null;
    }

    /*
     here we use Prepared Statements to prevent SQL injection attacks
     */

    /************************************ User ***********************************/
    private static String addUser(String phoneNumber, String password) {
        Connection connection = connect();
        String insertSQL = "INSERT INTO users (phone_number,password) VALUES (?, ?)";
        try {
            assert connection != null : "connection error";
            assert (phoneNumber.length() <= 10 && phoneNumber.matches("\\d+") && password.length() <= 50) : "invalid input";
            PreparedStatement preparedStatement = connection.prepareStatement(insertSQL, Statement.RETURN_GENERATED_KEYS);
            preparedStatement.setString(1, phoneNumber);
            preparedStatement.setString(2, password);
            int affectedRows = preparedStatement.executeUpdate();
            assert affectedRows > 0 : "error while inserting";
        } catch (SQLException | AssertionError exception) {
            exception.printStackTrace();
            return "sql error : " + exception.getMessage();
        }
        return "added new user with id = " + phoneNumber;
    }

    private static String findUser(@NotNull String phoneNumber, @NotNull String certainColumn) {
        Connection connection = connect();
        String findSQL = "Select * from users where phone_number = ?";
        try {
            assert connection != null : "connection error";
            assert (phoneNumber.length() <= 10 && phoneNumber.matches("\\d+")) : "invalid input";
            assert (certainColumn.equals("password") || certainColumn.equals("phone_number")) : "invalid chosen column";
            PreparedStatement preparedStatement = connection.prepareStatement(findSQL);
            preparedStatement.setString(1, phoneNumber);
            ResultSet user = preparedStatement.executeQuery();
            if (user.next())//if there is a user of this phone number + moving result cursor to read result
            {
                if (certainColumn.isBlank()) {
                    return user.getString("phone_number") + " , " + user.getString("password");
                } else return user.getString(certainColumn);
            } else //case the user doesn't exist
            {
                return "error: no user in such phone number";
            }
        } catch (SQLException | AssertionError exception) {
            exception.printStackTrace();
            return "sql error : " + exception.getMessage();
        }
    }

    /************************************ Contact ***********************************/
    private static String findContact(String adderNumber, String addedNumber) {
        Connection connection = connect();
        String findSQL = "Select * from contacts where adder_phone_number = ? and added_phone_number = ?";
        try {
            assert connection != null : "connection error";
            assert (adderNumber.length() <= 10 && addedNumber.length() <= 10 &&
                    adderNumber.matches("\\d+") && addedNumber.matches("\\d+")) : "invalid input";
            PreparedStatement preparedStatement = connection.prepareStatement(findSQL);
            preparedStatement.setString(1, adderNumber);
            preparedStatement.setString(2, addedNumber);
            ResultSet contact = preparedStatement.executeQuery();
            if (contact.next())//if there is a contact + moving result cursor to read result
            {
                return "adder: " + contact.getString("adder_phone_number") + " , " +
                        "added: " + contact.getString("added_phone_number");
            } else //case the contact doesn't exist
            {
                return "error: the added number not exist in the adder contact";
            }
        } catch (SQLException | AssertionError exception) {
            exception.printStackTrace();
            return "sql error : " + exception.getMessage();
        }
    }

    private static String addContact(String adderNumber, String addedNumber) {
        Connection connection = connect();
        String insertSQL = "INSERT INTO contacts (adder_phone_number, added_phone_number) VALUES (?, ?)";
        try {
            assert connection != null : "connection error";
            assert ((adderNumber.length() <= 10) && (addedNumber.length() <= 10) &&
                    adderNumber.matches("\\d+") && addedNumber.matches("\\d+")) : "invalid input";
            PreparedStatement preparedStatement = connection.prepareStatement(insertSQL, Statement.RETURN_GENERATED_KEYS);
            preparedStatement.setString(1, adderNumber);
            preparedStatement.setString(2, addedNumber);
            int affectedRows = preparedStatement.executeUpdate();
            assert affectedRows > 0 : "error while inserting";
        } catch (SQLException | AssertionError exception) {
            exception.printStackTrace();
            return "sql error : " + exception.getMessage();
        }
        return "added new contact " + addedNumber + " to the user " + adderNumber;
    }

    public static ArrayList<String> getContacts(String clientPhoneNumber) {
        Connection connection = connect();
        String findSQL = "Select added_phone_number from contacts where adder_phone_number = ?";
        try {
            assert connection != null : "connection error";
            assert (clientPhoneNumber.length() <= 10 && clientPhoneNumber.matches("\\d+")) : "invalid input";
            PreparedStatement preparedStatement = connection.prepareStatement(findSQL);
            preparedStatement.setString(1, clientPhoneNumber);
            ResultSet contacts = preparedStatement.executeQuery();
            ArrayList<String> contactResultList = new ArrayList<>();
            while (contacts.next()) {
                String str =contacts.getString("added_phone_number");
                System.out.println("in db connector "+ str);
                contactResultList.add(str);
            }
            if (contactResultList.isEmpty())//case no contact exist
            {
                ArrayList<String> error = new ArrayList<>();
                error.add("error: there is no contacts");
                return error;
            } else // return result
            {
                return contactResultList;
            }
        } catch (SQLException | AssertionError exception) {
            exception.printStackTrace();
            ArrayList<String> error = new ArrayList<>();
            error.add("sql error : " + exception.getMessage());
            return error;
        }
    }

    /************************************ Message ***********************************/
    private static String addMessage(String senderPhoneNumber, String receiverNumber, String message) {
        Connection connection = connect();
        String insertSQL = "INSERT INTO messages (content, sender_phone_number, receiver_phone_number) VALUES (?, ?, ?)";
        try {
            assert connection != null : "connection error";
            assert ((senderPhoneNumber.length() <= 10) && (receiverNumber.length() <= 10) &&
                    senderPhoneNumber.matches("\\d+") && receiverNumber.matches("\\d+")) : "invalid input";
            PreparedStatement preparedStatement = connection.prepareStatement(insertSQL, Statement.RETURN_GENERATED_KEYS);
            preparedStatement.setString(1, message);
            preparedStatement.setString(2, senderPhoneNumber);
            preparedStatement.setString(3, receiverNumber);
            int affectedRows = preparedStatement.executeUpdate();
            assert affectedRows > 0 : "error while inserting";
        } catch (SQLException | AssertionError exception) {
            exception.printStackTrace();
            return "sql error : " + exception.getMessage();
        }
        return "message is sent from " + senderPhoneNumber + " to the user " + receiverNumber;
    }

    public static ArrayList<HashMap> getMessages(String clientPhoneNumber) {
        Connection connection = connect();
        String findSQL = "Select * from messages where sender_phone_number = ? OR receiver_phone_number =?";
        try {
            assert connection != null : "connection error";
            assert (clientPhoneNumber.length() <= 10 && clientPhoneNumber.matches("\\d+")) : "invalid input";
            PreparedStatement preparedStatement = connection.prepareStatement(findSQL);
            preparedStatement.setString(1, clientPhoneNumber);
            preparedStatement.setString(2, clientPhoneNumber);
            ResultSet messages = preparedStatement.executeQuery();
            ArrayList<HashMap> messagesResultList = new ArrayList<>();
            while (messages.next()){
                HashMap row = new HashMap(4);
                row.put("sender_phone_number",messages.getString("sender_phone_number"));
                row.put("receiver_phone_number",messages.getString("receiver_phone_number"));
                row.put("content",messages.getString("content"));
                row.put("sent_at", messages.getObject("sent_at"));
                messagesResultList.add(row);
            }
            if (messagesResultList.isEmpty())//case no contact exist
            {
                HashMap error = new HashMap(1);
                ArrayList<HashMap> errors = new ArrayList<>();
                error.put("error" , "there is no messages");
                errors.add(error);
                return errors;
            } else // return result
            {
                return messagesResultList;
            }
        } catch (SQLException | AssertionError exception) {
            exception.printStackTrace();
            HashMap error = new HashMap(1);
            ArrayList<HashMap> errors = new ArrayList<>();
            error.put("error","sql error : " + exception.getMessage());
            errors.add(error);
            return errors;
        }
    }

    /*
     * here goes all methods that interact with db using a connection instance
     * */
    public static String signup(String phoneNumber, String password) {
        return addUser(phoneNumber, password);
    }

    public static String getUserHashedPassword(String phoneNumber) {
        return findUser(phoneNumber, "password");
    }

    public static String addingContact(String adderNumber, String addedNumber) {
        String findUserResult = findUser(addedNumber, "");
        String findContactResult = findContact(adderNumber, addedNumber);
        boolean userExist = !(findUserResult.contains("error"));
        boolean contactExist = !(findContactResult.contains("error"));
        if (userExist) {
            if (contactExist) {
                return findContactResult;
            } else //contact not exist (new addition)
            {
                return addContact(adderNumber, addedNumber);
            }
        } else {
            return findUserResult;
        }
    }

    public static String sendMessage(String senderPhoneNumber, String receiverNumber, String message) {
        return addMessage(senderPhoneNumber, receiverNumber, message);
    }

}
