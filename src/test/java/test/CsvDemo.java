package test;

import com.opencsv.CSVReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
public class CsvDemo {
    public String path;
    public CsvDemo(String path){
        this.path = path;
    }
    public CsvDemo(){
        this.path = null;
    }
    public ArrayList<List<Integer>> readCSV () throws Exception{
        ArrayList<List<Integer>> data = new ArrayList<>();
        CSVReader csvReader = new CSVReader(new FileReader(path));
        while (true) {
            String[] content = csvReader.readNext();
            if (content == null) {
                break;
            }
            ArrayList<Integer> list1 = new ArrayList<>();
            //遍历content
            for (String s : content) {
                double a = Double.parseDouble(s);
                a *= 1000;
                int b = (int) a;
                list1.add(b);
//                System.out.print(b+" ");
            }
            data.add(list1);
        }
        return data;
    }
    public ArrayList< List<Integer>> readCSV10 () throws Exception{
        ArrayList<List<Integer>> data = new ArrayList<>();
        CSVReader csvReader = new CSVReader(new FileReader(path));
        for(int i = 0;i<10;i++){
            String[] content = csvReader.readNext();
            if (content == null) {
                break;
            }
            ArrayList<Integer> list1 = new ArrayList<>();
            //遍历content
            for (String s : content) {
                double a = Double.parseDouble(s);
                a *= 10;
                int b = (int) a;
                list1.add(b);
//                System.out.print(b+" ");
            }
            data.add(list1);
        }
        return data;
    }

}
