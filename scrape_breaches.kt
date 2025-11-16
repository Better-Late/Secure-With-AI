#!/usr/bin/env kotlin

/**
 * Script to scrape data breaches from breachsense.com
 * Iterates through years 2020-2025 and all months
 *
 * Dependencies:
 * - OkHttp for HTTP requests
 * - JSoup for HTML parsing
 * - Kotlinx Serialization for JSON
 *
 * Gradle dependencies:
 * implementation("com.squareup.okhttp3:okhttp:4.12.0")
 * implementation("org.jsoup:jsoup:1.17.2")
 * implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.0")
 */

import okhttp3.OkHttpClient
import okhttp3.Request
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit

@Serializable
data class Breach(
    val name: String,
    val url: String,
    val year: Int,
    val month: String,
    val scrapedAt: String = LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME)
)

class BreachScraper {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    private val months = listOf(
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december"
    )

    /**
     * Convert month number (1-12) to lowercase month name
     */
    fun getMonthName(monthNum: Int): String {
        require(monthNum in 1..12) { "Month must be between 1 and 12" }
        return months[monthNum - 1]
    }

    /**
     * Scrape breach data for a specific year and month
     */
    fun scrapeBreachesForMonth(year: Int, month: String): List<Breach> {
        val url = "https://www.breachsense.com/breaches/$year/$month"
        println("Scraping: $url")

        val breaches = mutableListOf<Breach>()

        try {
            val request = Request.Builder()
                .url(url)
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    println("  Error: HTTP ${response.code}")
                    return emptyList()
                }

                val html = response.body?.string() ?: return emptyList()
                val doc: Document = Jsoup.parse(html)

                // Try the primary selector: article/div/h3/a
                var breachLinks = doc.select("article div h3 a")

                // Try alternative selector if primary fails
                if (breachLinks.isEmpty()) {
                    breachLinks = doc.select("h3 a")
                }

                breachLinks.forEach { link ->
                    val breachName = link.text().trim()
                    var breachUrl = link.attr("href")

                    // Make URL absolute if it's relative
                    if (breachUrl.isNotEmpty() && !breachUrl.startsWith("http")) {
                        breachUrl = "https://www.breachsense.com$breachUrl"
                    }

                    if (breachName.isNotEmpty()) {
                        breaches.add(
                            Breach(
                                name = breachName,
                                url = breachUrl,
                                year = year,
                                month = month
                            )
                        )
                    }
                }

                println("  Found ${breaches.size} breaches")
            }
        } catch (e: Exception) {
            println("  Error: ${e.message}")
        }

        return breaches
    }

    /**
     * Scrape all breaches from start_year to end_year
     */
    fun scrapeAllBreaches(startYear: Int = 2020, endYear: Int = 2025): List<Breach> {
        val allBreaches = mutableListOf<Breach>()

        for (year in startYear..endYear) {
            println("\n=== Year $year ===")

            for (monthNum in 1..12) {
                val monthName = getMonthName(monthNum)
                val breaches = scrapeBreachesForMonth(year, monthName)
                allBreaches.addAll(breaches)

                // Be polite and don't hammer the server
                Thread.sleep(1000)
            }
        }

        return allBreaches
    }

    /**
     * Save breaches to a JSON file
     */
    fun saveResultsJson(breaches: List<Breach>, outputFile: String = "breaches.json") {
        val json = Json { prettyPrint = true }
        val jsonString = json.encodeToString(breaches)

        File(outputFile).writeText(jsonString)
        println("\n✓ Saved ${breaches.size} breaches to $outputFile")
    }

    /**
     * Save breaches to a CSV file
     */
    fun saveResultsCsv(breaches: List<Breach>, outputFile: String = "breaches.csv") {
        if (breaches.isEmpty()) {
            println("No breaches to save")
            return
        }

        File(outputFile).bufferedWriter().use { writer ->
            // Write header
            writer.write("name,url,year,month,scraped_at\n")

            // Write data rows
            breaches.forEach { breach ->
                val row = listOf(
                    escapeCSV(breach.name),
                    escapeCSV(breach.url),
                    breach.year.toString(),
                    escapeCSV(breach.month),
                    escapeCSV(breach.scrapedAt)
                ).joinToString(",")

                writer.write("$row\n")
            }
        }

        println("✓ Saved ${breaches.size} breaches to $outputFile")
    }

    /**
     * Escape CSV field values (handle commas, quotes, newlines)
     */
    private fun escapeCSV(value: String): String {
        return if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            "\"${value.replace("\"", "\"\"")}\""
        } else {
            value
        }
    }
}

fun main() {
    println("Starting breach scraper...")
    println("Scraping years 2020-2025, all months\n")

    val scraper = BreachScraper()

    // Scrape all breaches
    val breaches = scraper.scrapeAllBreaches(startYear = 2020, endYear = 2025)

    // Print summary
    println("\n${"=".repeat(60)}")
    println("SUMMARY")
    println("=".repeat(60))
    println("Total breaches found: ${breaches.size}")

    if (breaches.isNotEmpty()) {
        // Show first few examples
        println("\nFirst 5 breaches:")
        breaches.take(5).forEach { breach ->
            println("  - ${breach.name} (${breach.year}/${breach.month})")
        }

        // Save results
        scraper.saveResultsJson(breaches, "breaches.json")
        scraper.saveResultsCsv(breaches, "breaches.csv")
    } else {
        println("\n⚠️  No breaches found. The website structure may have changed.")
        println("    Try inspecting the page manually to verify the HTML structure.")
    }
}
