package br.com.gsistemas.gateway.util;

import org.springframework.boot.Banner;
import org.springframework.core.env.Environment;

import java.io.PrintStream;

public class CustomBanner implements Banner {
    @Override
    public void printBanner(Environment environment, Class<?> sourceClass, PrintStream out) {
        out.println("""
                 ,----.    ,---. ,--. ,---.,--------.,------.,--.   ,--.  ,---.   ,---.
                '  .-./   '   .-'|  |'   .-'--.  .--'|  .---'|   `.'   | /  O  \\ '   .-'
                |  | .---.`.  `-.|  |`.  `-.  |  |   |  `--, |  |'.'|  ||  .-.  |`.  `-.
                '  '--'  |.-'    |  |.-'    | |  |   |  `---.|  |   |  ||  | |  |.-'    |
                 `------' `-----'`--'`-----'  `--'   `------'`--'   `--'`--' `--'`-----'
                """);
        out.println("#####################################################");
        out.println(String.format("#\t:: Application name :: \t\t %s \t\t\t#",
                environment.getProperty("spring.application.name")));
        out.println(String.format("#\t:: Application version :: \t %s \t\t\t\t#",
                environment.getProperty("application.version")));
        out.println(String.format("#\t:: Application port :: \t\t %s \t\t\t\t#",
                environment.getProperty("server.port")));
        out.println(String.format("#\t:: Author :: \t\t\t\t %s \t\t\t#",
                environment.getProperty("application.author")));
        out.println("#####################################################");
    }
}
