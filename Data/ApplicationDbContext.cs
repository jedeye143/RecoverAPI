using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RecoverPH_API.Models;

namespace RecoverPH_API.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }

        // Add PaymentTransactions table
        public DbSet<PaymentTransaction> PaymentTransactions { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configure PaymentTransaction entity
            builder.Entity<PaymentTransaction>(entity =>
            {
                entity.HasKey(e => e.Id);
                
                entity.Property(e => e.TransactionId)
                    .IsRequired()
                    .HasMaxLength(100);

                entity.Property(e => e.CheckoutId)
                    .IsRequired()
                    .HasMaxLength(100);

                entity.Property(e => e.Amount)
                    .HasColumnType("decimal(18,2)")
                    .IsRequired();

                entity.Property(e => e.Currency)
                    .HasMaxLength(3)
                    .HasDefaultValue("PHP");

                entity.Property(e => e.CreatedAt)
                    .HasDefaultValueSql("GETUTCDATE()");

                // Create index on UserId for better query performance
                entity.HasIndex(e => e.UserId)
                    .HasDatabaseName("IX_PaymentTransactions_UserId");

                // Create index on TransactionId for uniqueness
                entity.HasIndex(e => e.TransactionId)
                    .IsUnique()
                    .HasDatabaseName("IX_PaymentTransactions_TransactionId");

                // Create index on CheckoutId
                entity.HasIndex(e => e.CheckoutId)
                    .HasDatabaseName("IX_PaymentTransactions_CheckoutId");

                // Create index on Status for filtering
                entity.HasIndex(e => e.Status)
                    .HasDatabaseName("IX_PaymentTransactions_Status");

                // Configure relationship with ApplicationUser
                entity.HasOne(e => e.User)
                    .WithMany()
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}


