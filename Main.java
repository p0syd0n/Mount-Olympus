public class Main {
    public static void main(String[] args) {
String str = "RAM";
for (int i = str.length(); i > 0; i--) 
{
  for (int j = 1; j <= 3; j++) 
  {
    System.out.print(str.substring(i - 1, i));
  }
} 
    }
}