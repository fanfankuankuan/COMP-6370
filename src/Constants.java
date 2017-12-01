package com;

public class Constants {

	// All the constants required in the Needham-Schroeder protocol
	public static String INITIATE_CONVERSATION = "This is Alice, Here is the Session Key.";
	
	public static int ALICE = 1;
	public static int BOB = 2;
	public static int KDC = 3;
	
	public static String K_ALICE_KDC = "a;lskdjf;laksjdf;lkja";
	public static String K_BOB_KDC = "b;dsjflaksd;ewqfljaw;zcvs";
	
	public static String CBC_ALGORITHM_WITH_PADDING = "DESede/CBC/PKCS5Padding";
	public static String ECB_ALGORITHM = "DESede/ECB/PKCS5Padding";
	public static String CBC_ALGORITHM_WITHOUT_PADDING = "DESede/CBC/NoPadding";
	public static String ECB_ALGORITHM_WITHOUT_PADDING = "DESede/ECB/NoPadding";
	
	public static String INVALID_INPUT_STRING_LENGTH = "Invalid input string length. Alice is not authenticated !!!!";
	
}
