package demo;

import com.google.common.base.Objects;

public class App {
    private final String name = "mendr";

    @Override
    public String toString() {
        // Objects.toStringHelper was removed in Guava 21.
        return Objects.toStringHelper(this).add("name", name).toString();
    }
}
