package application;
import java.sql.*;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;

import org.bouncycastle.util.Arrays;

import Encryption.EncryptionHelper;
import Encryption.EncryptionUtils;

class DatabaseHelper {

	// JDBC driver name and database URL 
	static final String JDBC_DRIVER = "org.h2.Driver";   
	static final String DB_URL = "jdbc:h2:~/firstDatabase";  

	//  Database credentials 
	static final String USER = "sa"; 
	static final String PASS = ""; 
	private Connection connection = null;
	private Statement statement = null; 
	//	PreparedStatement pstmt
	
	private EncryptionHelper encryptionHelper;
	
	public DatabaseHelper() throws Exception {
		encryptionHelper = new EncryptionHelper();
	}

	public void connectToDatabase() throws SQLException {
		try {
			Class.forName(JDBC_DRIVER); // Load the JDBC driver
			System.out.println("Connecting to database...");
			connection = DriverManager.getConnection(DB_URL, USER, PASS);
			statement = connection.createStatement(); 
			createTables();  // Create the necessary tables if they don't exist
		} catch (ClassNotFoundException e) {
			System.err.println("JDBC Driver not found: " + e.getMessage());
		}
	}

	private void createTables() throws SQLException {
		String userTable = "CREATE TABLE IF NOT EXISTS cse360users ("
				+ "id INT AUTO_INCREMENT PRIMARY KEY, "
				+ "email VARCHAR(255) UNIQUE, "
				+ "password VARCHAR(255), "
				+ "role VARCHAR(20))";
		String articleTable = "CREATE TABLE IF NOT EXISTS articles (" 
				+ "id INT AUTO_INCREMENT PRIMARY KEY, "
				+ "title VARCHAR(255) UNIQUE, "
				+ "authors VARCHAR(255), "
				+ "abstr VARCHAR(255), "
				+ "keywords VARCHAR(255), "
				+ "body VARCHAR(10000), "
				+ "references VARCHAR(1000))";
							  
		statement.execute(userTable);
		statement.execute(articleTable);
	}


	// Check if the database is empty
	public boolean isDatabaseEmpty() throws SQLException {
		String query = "SELECT COUNT(*) AS count FROM cse360users";
		ResultSet resultSet = statement.executeQuery(query);
		if (resultSet.next()) {
			return resultSet.getInt("count") == 0;
		}
		return true;
	}
	
	public boolean isArticleTableEmpty() throws SQLException {
		String query = "SELECT COUNT(*) AS count from articles";
		ResultSet rs = statement.executeQuery(query);
		if(rs.next())
			return rs.getInt("count") == 0;
		return true;
	}

	public void register(String email, String password, String role) throws Exception {
		String encryptedPassword = Base64.getEncoder().encodeToString(
				encryptionHelper.encrypt(password.getBytes(), EncryptionUtils.getInitializationVector(email.toCharArray()))
		);
		
		String insertUser = "INSERT INTO cse360users (email, password, role) VALUES (?, ?, ?)";
		try (PreparedStatement pstmt = connection.prepareStatement(insertUser)) {
			pstmt.setString(1, email);
			pstmt.setString(2, encryptedPassword);
			pstmt.setString(3, role);
			pstmt.executeUpdate();
		}
	}
	
	
	//delete article from database based on title
	public void deleteArticle(String title) throws Exception{
		String deleteArticle = "DELETE FROM articles WHERE title='" + title + "'";
		statement.execute(deleteArticle);
				
	}
	
	//register article to database everything except for title who will be used to get IV
	public void registerArticle(String title, String authors, String abstr, String keywords, String body, String references) throws Exception
	{
		String encryptedAuthors = Base64.getEncoder().encodeToString(
				encryptionHelper.encrypt(authors.getBytes(), EncryptionUtils.getInitializationVector(title.toCharArray())));
		String encryptedAbstr = Base64.getEncoder().encodeToString(
				encryptionHelper.encrypt(abstr.getBytes(), EncryptionUtils.getInitializationVector(title.toCharArray())));
		String encryptedKeywords = Base64.getEncoder().encodeToString(
				encryptionHelper.encrypt(keywords.getBytes(), EncryptionUtils.getInitializationVector(title.toCharArray())));
		String encryptedBody = Base64.getEncoder().encodeToString(
				encryptionHelper.encrypt(body.getBytes(), EncryptionUtils.getInitializationVector(title.toCharArray())));
		String encryptedReferences = Base64.getEncoder().encodeToString(
				encryptionHelper.encrypt(references.getBytes(), EncryptionUtils.getInitializationVector(title.toCharArray())));
		String insertArticle = "INSERT INTO articles (title, authors, abstr, keywords, body, references) VALUES (?, ?, ?, ?, ?, ?)";
		try(PreparedStatement pstmt = connection.prepareStatement(insertArticle)) { 
			pstmt.setString(1,  title);
			pstmt.setString(2,  encryptedAuthors);
			pstmt.setString(3,  encryptedAbstr);
			pstmt.setString(4,  encryptedKeywords);
			pstmt.setString(5,  encryptedBody);
			pstmt.setString(6,  encryptedReferences);
			pstmt.executeUpdate();
		}
	}

	public boolean login(String email, String password, String role) throws Exception {
		String encryptedPassword = Base64.getEncoder().encodeToString(
				encryptionHelper.encrypt(password.getBytes(), EncryptionUtils.getInitializationVector(email.toCharArray()))
		);	
		
		String query = "SELECT * FROM cse360users WHERE email = ? AND password = ? AND role = ?";
		try (PreparedStatement pstmt = connection.prepareStatement(query)) {
			pstmt.setString(1, email);
			pstmt.setString(2, encryptedPassword);
			pstmt.setString(3, role);
			try (ResultSet rs = pstmt.executeQuery()) {
				return rs.next();
			}
		}
	}
	
	public boolean doesUserExist(String email) {
	    String query = "SELECT COUNT(*) FROM cse360users WHERE email = ?";
	    try (PreparedStatement pstmt = connection.prepareStatement(query)) {
	        
	        pstmt.setString(1, email);
	        ResultSet rs = pstmt.executeQuery();
	        
	        if (rs.next()) {
	            // If the count is greater than 0, the user exists
	            return rs.getInt(1) > 0;
	        }
	    } catch (SQLException e) {
	        e.printStackTrace();
	    }
	    return false; // If an error occurs, assume user doesn't exist
	}

	public void displayUsersByAdmin() throws Exception{
		String sql = "SELECT * FROM cse360users"; 
		Statement stmt = connection.createStatement();
		ResultSet rs = stmt.executeQuery(sql); 

		while(rs.next()) { 
			// Retrieve by column name 
			int id  = rs.getInt("id"); 
			String  email = rs.getString("email"); 
			String role = rs.getString("role");  
			String encryptedPassword = rs.getString("password"); 
			char[] decryptedPassword = EncryptionUtils.toCharArray(
					encryptionHelper.decrypt(
							Base64.getDecoder().decode(
									encryptedPassword
							), 
							EncryptionUtils.getInitializationVector(email.toCharArray())
					)	
			);

			// Display values 
			System.out.print("ID: " + id); 
			System.out.print(", Email: " + email); 
			System.out.print(", Password: "); 
			EncryptionUtils.printCharArray(decryptedPassword);
			System.out.println(", Role: " + role); 
			
			Arrays.fill(decryptedPassword, '0');
		} 
	}
	
	
	//Display all articles id, title, and author(s)
	public void displayArticles() throws Exception {
		String sql = "SELECT * FROM articles";
		Statement stmt = connection.createStatement();
		ResultSet rs = stmt.executeQuery(sql);
		
		while(rs.next())
		{
			//get each column from the database then list it and repeat until at the end of the table
			int id = rs.getInt("id");
			String title = rs.getString("title");
			String encryptedAuthors = rs.getString("authors");
			char[] decryptedAuthors = EncryptionUtils.toCharArray(
					encryptionHelper.decrypt(
							Base64.getDecoder().decode(
									encryptedAuthors
							), 
							EncryptionUtils.getInitializationVector(title.toCharArray())
					)	
			);
			System.out.print("ID: " + id);
			System.out.print(", Title: " + title);
			System.out.print(", Author(s): ");
			EncryptionUtils.printCharArray(decryptedAuthors);
			System.out.println();
			Arrays.fill(decryptedAuthors, '0');		//fill the decrypted array
		}
	}
	
	public void displayUsersByUser() throws Exception{
		String sql = "SELECT * FROM cse360users"; 
		Statement stmt = connection.createStatement();
		ResultSet rs = stmt.executeQuery(sql); 

		while(rs.next()) { 
			// Retrieve by column name 
			int id  = rs.getInt("id"); 
			String  email = rs.getString("email"); 
			String role = rs.getString("role");  
			String encryptedPassword = rs.getString("password"); 
			char[] decryptedPassword = EncryptionUtils.toCharArray(
					encryptionHelper.decrypt(
							Base64.getDecoder().decode(
									encryptedPassword
							), 
							EncryptionUtils.getInitializationVector(email.toCharArray())
					)	
			);

			// Display values 
			System.out.print("ID: " + id); 
			System.out.print(", Email: " + email); 
			System.out.print(", Password: "); 
			EncryptionUtils.printCharArray(decryptedPassword);
			System.out.println(", Role: " + role); 
			Arrays.fill(decryptedPassword, '0');
		} 
	}

	public void closeConnection() {
		try{ 
			if(statement!=null) statement.close(); 
		} catch(SQLException se2) { 
			se2.printStackTrace();
		} 
		try { 
			if(connection!=null) connection.close(); 
		} catch(SQLException se){ 
			se.printStackTrace(); 
		} 
	}

}
