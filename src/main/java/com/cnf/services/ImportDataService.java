package com.cnf.services;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import com.cnf.entity.Category;
import com.cnf.entity.Product;
import com.cnf.helper.ImportHelper;
import com.cnf.repository.ICategoryRepository;
import com.cnf.repository.IProductRepository;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;


@Service
public class ImportDataService {
    @Autowired
    IProductRepository repository;

    @Autowired
    ICategoryRepository categoryRepository;

    public static String TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    static String[] HEADERs = {"active", "description", "discount", "img", "name", "price", "quantity", "weight", "category_id"};
    static String SHEET = "ProductImport";

    public static boolean hasExcelFormat(MultipartFile file) {

        if (!TYPE.equals(file.getContentType())) {
            return false;
        }
        return true;
    }

    public void save(MultipartFile file) {
        try {
            List<Product> tutorials = excelToTutorials(file.getInputStream());
            repository.saveAll(tutorials);
        } catch (IOException e) {
            throw new RuntimeException("fail to store excel data: " + e.getMessage());
        }
    }

    public ByteArrayInputStream load() {
        List<Product> tutorials = repository.findAll();

        ByteArrayInputStream in = ImportHelper.tutorialsToExcel(tutorials);
        return in;
    }

    public List<Product> getAllTutorials() {
        return repository.findAll();
    }

    public List<Product> excelToTutorials(InputStream is) {
//        try {
//            Workbook workbook = new XSSFWorkbook(is);
//
//            Sheet sheet = workbook.getSheet(SHEET);
//            Iterator<Row> rows = sheet.iterator();
//
//            List<Product> tutorials = new ArrayList<Product>();
//
//            int rowNumber = 0;
//            while (rows.hasNext()) {
//                Row currentRow = rows.next();
//
//                // skip header
//                if (rowNumber == 0) {
//                    rowNumber++;
//                    continue;
//                }
//
//                Iterator<Cell> cellsInRow = currentRow.iterator();
//
//                Product tutorial = new Product();
//
//                int cellIdx = 0;
//                while (cellsInRow.hasNext()) {
//                    Cell currentCell = cellsInRow.next();
//
//                    switch (cellIdx) {
//
//                        case 0:
//                            tutorial.setName(currentCell.getStringCellValue());
//                            break;
//
//                        case 1:
//                            tutorial.setDescription(currentCell.getStringCellValue());
//                            break;
//
//                        case 2:
//                            tutorial.setPrice(currentCell.getNumericCellValue());
//                            break;
//                        case 3:
//                            tutorial.setQuantity((float) currentCell.getNumericCellValue());
//                            break;
//                        case 4:
//                            tutorial.setWeight((float) currentCell.getNumericCellValue());
//                            break;
//                        case 5:
//                            tutorial.setImg(currentCell.getStringCellValue());
//                            break;
//                        case 6:
//                            long categoryId = (long) currentCell.getNumericCellValue();
//                            CategoryService category = new CategoryService();
//                            tutorial.setCategory(category.findCategoryById(categoryId));
//                            break;
//                        default:
//                            break;
//                    }
//
//                    cellIdx++;
//                }
//
//                tutorials.add(tutorial);
//            }
//
//            workbook.close();
//
//            return tutorials;
//        } catch (IOException e) {
//            throw new RuntimeException("fail to parse Excel file: " + e.getMessage());
//        }
        try {
            Workbook workbook = new XSSFWorkbook(is);
            Sheet sheet = workbook.getSheet(SHEET);
            List<Product> products = new ArrayList<>();

            for (int rowIndex = 1; rowIndex <= sheet.getLastRowNum(); rowIndex++) {
                Row row = sheet.getRow(rowIndex);
                Product product = new Product();
                product.setActive(row.getCell(0).getBooleanCellValue());
                product.setDescription(row.getCell(1).getStringCellValue());
                product.setDiscount((int) row.getCell(2).getNumericCellValue());
                product.setImg(row.getCell(3).getStringCellValue());
                product.setName(row.getCell(4).getStringCellValue());
                product.setPrice(row.getCell(5).getNumericCellValue());
                product.setQuantity((int) row.getCell(6).getNumericCellValue());
                product.setWeight((float) row.getCell(7).getNumericCellValue());
                Long categoryId = (long) row.getCell(8).getNumericCellValue();
                Category category = categoryRepository.findById(categoryId)
                        .orElseThrow(() -> new RuntimeException("Category not found with ID: " + categoryId));
                product.setCategory(category);
                products.add(product);
            }

            workbook.close();
            return products;
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse Excel file: " + e.getMessage());
        }
    }
}
