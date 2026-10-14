package demo;

import com.fasterxml.jackson.databind.ObjectMapper;

public class App {
    public static void main(String[] args) throws Exception {
        System.out.println(new ObjectMapper().readTree("[1, 2]"));
    }
}
