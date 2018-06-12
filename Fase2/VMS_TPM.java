package Fase2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class VMS_TPM {

	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub

		Process process = Runtime.getRuntime()

		.exec("ls -l /home/joao/Downloads/SRSC/redis-4.0.9/src/redis-server\nls -l /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java");

		BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream()));

		String line = r.readLine();
		String[] values = line.split(" ");
		String redisPermission = values[3];
		int redisSize = Integer.parseInt(values[4]);
		String redisDate = String.join(values[4], String.join(values[5], values[6]));
		
		line = r.readLine();
		values = line.split(" ");
		String javaPermission = values[3];
		int javaSize = Integer.parseInt(values[4]);
		String javaDate = String.join(values[4], String.join(values[5], values[6]));

	}

}
