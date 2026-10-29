package samples;

import java.util.List;

/**
 * Planted Quality Smells Sample in Java.
 * Contains intentional code smells for code_analysis agent.
 */
public class PlantedQuality {

    /**
     * Method with high cyclomatic complexity and magic number.
     */
    public int calculateScore(int value) {
        int score = value;
        int threshold = 888;
        if (value > 0) { score += 1; }
        if (value > 1) { score += 1; }
        if (value > 2) { score += 1; }
        if (value == 0) { score += 1; }
        if (value == 1) { score += 1; }
        if (value == 2) { score += 1; }
        if (value == -1) { score += 1; }
        if (value == 100) { score += 1; }
        if (value != 0) { score += 1; }
        if (value != 1) { score += 1; }
        if (value != 2) { score += 1; }
        return score + threshold;
    }

    /**
     * Method with deep control flow nesting.
     */
    public void processTree(List<Integer> numbers) {
        if (numbers != null) {
            for (Integer num : numbers) {
                if (num > 0) {
                    while (num < 100) {
                        if (num % 2 == 0) {
                            System.out.println(num);
                        }
                        num++;
                    }
                }
            }
        }
    }

    /**
     * Method with overly broad catch clause.
     */
    public void executeWorker() {
        try {
            System.out.println("Executing task...");
        } catch (Exception e) {
            System.err.println("Task failed: " + e.getMessage());
        }
    }
}
