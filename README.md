A basic certificate validator written in C

Input: 
A CSV (.csv) file that contains two columns, the first containing a file path to the certificate, the second column being the URL of the certificate.

Output:
A CSV file called output.csv. It contains one line per certificate checked, in the same order as the input CSV file. Each line contains three columns, the two columns from the input file, and a third column containing either the value 1 if the certificate is valid, or 0 if the certificate is invalid.

An example input file is shown below:
cert one.cer,www.comp30023test.com cert two.cert,game1.onlinegaming.com
  
An example output file is shown below:
cert one.cer,www.comp30023test.com,1 cert two.cert,game1.onlinegaming.com,0

Command line arguments: ./certcheck pathToTestFile
