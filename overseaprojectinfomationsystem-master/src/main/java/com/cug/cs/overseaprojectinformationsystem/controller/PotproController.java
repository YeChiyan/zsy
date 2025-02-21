package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.*;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.PageBean;
import com.cug.cs.overseaprojectinformationsystem.dal.entitys.PotProject;
import com.cug.cs.overseaprojectinformationsystem.dao.ExcelPotDao;
import com.cug.cs.overseaprojectinformationsystem.service.PotproService;
import com.cug.cs.overseaprojectinformationsystem.util.ExcelUtil;
import com.cug.cs.overseaprojectinformationsystem.util.PathUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.List;

/**
 * @className: PotproController
 * @author: Zhangz
 * @description: TODO 用户进行潜在项目管理
 * @date: 2023/9/15 22:18
 * @version: 1.0
 */

@Slf4j
@RestController
@RequestMapping("/market")
public class PotproController {

    @Autowired
    private PotproService potproService;

    /*
    插入潜在项目
     */
    @PostMapping("/potproject")
    public ResponseData addPotproject(@RequestBody PotProject potProject){

        log.info("进行潜在项目插入操作");
        potproService.addPotproject(potProject);
        return new ResponseUtil<PotProject>().setData(potProject, "success");
    }

    /*
    分页查询项目
     */
    @GetMapping("/potproject")
    public ResData selectPotproject(PageBaseInfo pageBaseInfo){
       PageBean pageBean = potproService.selectPotproject(pageBaseInfo);
       return new ResUtil<PageBean>().setData(pageBean,"success");
   }


   @DeleteMapping("/potproject")
   public ResponseData deletePotproject(Integer projectId){
       log.info("批量删除删除潜在项目");
       potproService.delete(projectId);
       return new ResponseUtil<>().setData(null,"message");
   }

   //更新项目信息
    @PutMapping("/potproject")
   public ResponseData updatePotproject(@RequestBody PotProject potProject){
       log.info("修改");
       potproService.updatePotproject(potProject);
       return new ResponseUtil<>().setData(null,"message");

   }

    @Autowired
    ExcelPotDao excelPotDao;
    @ResponseBody
    @RequestMapping("/potexcel")
    public void potExport(HttpServletResponse response) throws IOException {
        String fileName = "潜在项目.xlsx";
        String[] sheetName = {"潜在项目"};
        String[] title = {"海外中心","项目名称","国家","客户","工作量","合同额（万美元）","类型","落实程度","重要动态"};
        List<PotProject> potPorjectlist = excelPotDao.selectList(null);
        String[][] content = new String[potPorjectlist.size()][title.length];
        log.info("——————————————————————准备工作完成——————————————————————");
        //导出合同管理表格
        log.info("——————————————————————准备工作完成——————————————————————");
        //导出潜在项目
        for (int i = 0;i<potPorjectlist.size();i++){
            String[] row = content[i];
            PotProject potProject = potPorjectlist.get(i);
            row[0] = potProject.getCenterName();
            row[1] = potProject.getProjectName();
            row[2] = potProject.getCountry();
            row[3] = potProject.getClientName();
            row[4] = potProject.getWorkloadKm()+"km"+ potProject.getWorkloadSqkm()+"sqkm";
            row[5] = String.valueOf(potProject.getContract());
            row[6] = potProject.getConType();
            row[7] = potProject.getFulfilExtent();
            row[8] = potProject.getImpActive();
        }
        log.info("————————————————————潜在项目导出完成————————————————————");

        XSSFWorkbook workbook = ExcelUtil.getWorkbook(sheetName, title, content,false);
        log.info("-————————————————————数据已写入文件————————————————————-");

        // TODO 这里路径写死了，前端可以传一个路径进来，不同的用户路径是不同的
        String path = PathUtil.getPath()+fileName;
        log.info(path);

        FileOutputStream out = new FileOutputStream(new File(path));
        workbook.write(out);
        log.info("——————————————————————文件已输出——————————————————————");

        try{
            URL url = new File(path).toURI().toURL();
            URLConnection conn = url.openConnection();
            InputStream inputStream = conn.getInputStream();
            response.reset();
            response.setContentType(conn.getContentType());
            String filename = "潜在项目.xlsx";
            response.setHeader("Content-Disposition", "attachment; filename=" + URLEncoder.encode(filename, "UTF-8"));
            byte[] buffer = new byte[1024];
            int len;
            OutputStream outputStream = response.getOutputStream();
            while ((len = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, len);
            }
            inputStream.close();
        }
        catch (IOException e){
            throw new IOException(e);
        }
    }
}
